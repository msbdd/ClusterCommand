import paramiko
import yaml
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import csv
import contextlib
import os
import re


def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def ssh_connect(
    ip, username, key_filename=None, password=None, policy="reject",
    timeout="10"
):
    client = paramiko.SSHClient()

    try:
        client.load_system_host_keys()
    except IOError:
        pass

    if policy.lower() == "auto":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    elif policy.lower() == "warning":
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    try:
        client.connect(
            ip,
            username=username,
            key_filename=key_filename,
            password=password,
            timeout=timeout,
        )
        return client
    except paramiko.BadHostKeyException as e:
        raise ConnectionError(
            f"Host key mismatch for {ip}. Potential Security Risk! Error: {e}"
        )
    except paramiko.AuthenticationException as e:
        auth_methods = []
        if key_filename:
            auth_methods.append(f"Key file: {key_filename}")
        if password:
            auth_methods.append("Password")
        raise ConnectionError(
            f"Authentication failed for {ip} (User: {username})."
            f" Attempted: {', '.join(auth_methods)}. Error: {e}"
        )
    except Exception as e:
        raise ConnectionError(f"General connection error for {ip}: {e}")


def run_ssh_command(client, cmd):
    transport = client.get_transport()
    if transport is None:
        raise paramiko.SSHException("Transport is not active.")

    channel = transport.open_session()
    channel.exec_command(cmd)

    stdout = channel.makefile("r", -1)
    stderr = channel.makefile_stderr("r", -1)

    out = stdout.read().decode()
    err = stderr.read().decode()

    code = channel.recv_exit_status()

    channel.close()
    return out, err, code


def upload_file(client, local, remote):
    with contextlib.closing(client.open_sftp()) as sftp:
        sftp.put(local, remote)


def download_file(client, remote, local):
    with contextlib.closing(client.open_sftp()) as sftp:
        sftp.get(remote, local)


def evaluate_condition(condition, context):
    pattern = r'(\w+)\s+(contains|equals|not_contains|not_equals|regex)\s+(.+)'
    match = re.match(pattern, condition.strip())

    if not match:
        raise ValueError(f"Invalid condition format: {condition}")

    var_name, operator, value = match.groups()
    value = value.strip()

    if var_name not in context:
        return False

    var_value = str(context[var_name])

    if operator == "contains":
        return value in var_value
    elif operator == "not_contains":
        return value not in var_value
    elif operator == "equals":
        return var_value == value
    elif operator == "not_equals":
        return var_value != value
    elif operator == "regex":
        return re.search(value, var_value) is not None

    return False


def execute_commands(commands, client, log, fetch_data, context, final_config):
    for step in commands:
        step_type = step.get("type")

        if step_type == "conditional":
            condition = step.get("if")
            if not condition:
                log.append("[ERROR] Conditional step missing 'if' clause")
                return False

            try:
                result = evaluate_condition(condition, context)
                log.append(f"[CONDITION] '{condition}' -> {result}")

                if result:
                    branch = step.get("then", [])
                    if branch:
                        log.append("[BRANCH] Executing 'then' branch")
                        if not execute_commands(branch, client, log,
                                                fetch_data, context,
                                                final_config):
                            return False
                else:
                    branch = step.get("else", [])
                    if branch:
                        log.append("[BRANCH] Executing 'else' branch")
                        if not execute_commands(branch, client, log,
                                                fetch_data, context,
                                                final_config):
                            return False
            except Exception as e:
                log.append(f"[ERROR] Condition evaluation failed: {e}")
                return False

        elif step_type == "upload":
            local = step["local"]
            remote = step["remote"]
            try:
                upload_file(client, local, remote)
                log.append(f"[UPLOAD OK] {local} → {remote}")
            except Exception as e:
                log.append(f"[UPLOAD ERROR] Failed to upload {local}: {e}")
                return False

        elif step_type == "download":
            remote = step["remote"]
            download_dir = final_config.get(
                "download_folder",
                os.path.join(final_config.get("output_folder", "."),
                             "downloads")
            )
            os.makedirs(download_dir, exist_ok=True)
            base = os.path.basename(remote)
            local = f"{context.get('_ip', 'unknown')}_{base}"
            local_path = os.path.join(download_dir, local)

            try:
                download_file(client, remote, local_path)
                log.append(f"[DOWNLOAD OK] {remote} → {local_path}")
            except Exception as e:
                log.append(f"[DOWNLOAD ERROR] Failed to "
                           f"download {remote}: {e}")
                return False

        elif step_type == "run" or step_type == "fetch":
            cmd = step["cmd"]
            log.append(f"\n> {cmd}")

            out, err, code = run_ssh_command(client, cmd)
            log.append(out.strip())
            if err:
                log.append("ERR: " + err.strip())

            if "store_as" in step:
                var_name = step["store_as"]
                context[var_name] = out.strip()
                log.append(f"[STORED] Output saved to variable '{var_name}'")

            if "expect_exit" in step and code != step["expect_exit"]:
                log.append(
                    f"[ERROR] Unexpected exit code {code}. "
                    f"Expected {step['expect_exit']}"
                )
                return False

            if "expect" in step:
                expected = step.get("expect", "")
                if expected not in out:
                    log.append("[ERROR] Expected output missing.")
                    log.append(f"Missing: {expected}")
                    return False

            if step_type == "fetch":
                lines = out.strip().splitlines()
                for line in lines:
                    if line.strip():
                        fetch_data.append((context.get('_ip', 'unknown'),
                                           line.strip()))

        else:
            log.append(f"[ERROR] Invalid step type: {step_type}")
            return False

    return True


def execute_plan(ip, config, defaults):
    final_config = defaults.copy()
    final_config.update(config)

    username = final_config["username"]
    key_filename = final_config.get("key_filename")
    password = final_config.get("password")

    host_key_policy = final_config.get("host_key_policy", "reject")
    connection_timeout = final_config.get("connection_timeout", "10")
    commands = final_config.get("commands", [])

    log = [
        f"=== {ip} - START: {datetime.datetime.now().strftime('%H:%M:%S')} ==="
    ]
    fetch_data = []
    context = {"_ip": ip}
    if not key_filename and not password:
        log.append(
            f"[ERROR] No 'key_filename' or 'password'"
            f" provided for {ip}. Skipping."
        )
        return "\n".join(log), fetch_data

    try:
        timeout = float(connection_timeout)
    except Exception:
        log.append(
            "Incorrect timeout time, using defaults"
        )
        timeout = 10

    try:

        client = ssh_connect(
            ip,
            username,
            key_filename=key_filename,
            password=password,
            policy=host_key_policy,
            timeout=timeout
        )
    except ConnectionError as e:
        log.append(f"[ERROR] SSH connection failed: {e}")
        return "\n".join(log), fetch_data
    except Exception as e:
        log.append(f"[ERROR] Unexpected connection error: {e}")
        return "\n".join(log), fetch_data

    try:
        success = execute_commands(commands, client, log, fetch_data,
                                   context, final_config)
        if not success:
            return "\n".join(log), fetch_data
    finally:
        client.close()

    log.append(
        f"=== {ip} - SUCCESS: "
        f"{datetime.datetime.now().strftime('%H:%M:%S')} ==="
    )
    return "\n".join(log), fetch_data


def main():
    parser = argparse.ArgumentParser(
        description="ClusterCommand: SSH-based parallel communication tool"
    )
    parser.add_argument(
        "config",
        type=str,
        nargs="?",
        default="config.yaml",
        help="Path to the YAML configuration file (default: config.yaml)",
    )
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"[CRITICAL] Configuration file not found at: {args.config}")
        return

    defaults = cfg.get("defaults", {})
    servers = cfg.get("servers", [])

    if not servers:
        print("[WARNING] No servers defined in the config file. Exiting.")
        return
    output_folder = defaults.get("output_folder", ".")
    if output_folder != ".":
        try:
            os.makedirs(output_folder, exist_ok=True)
            print(f"[INFO] Saving logs to directory: {output_folder}")
        except OSError as e:
            print(f"[CRITICAL] Could not create output folder "
                  f"'{output_folder}': {e}")
            return
    timestamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    logfile = os.path.join(output_folder,
                           f"ClusterCommand_log_{timestamp}.txt")
    fetchfile = os.path.join(output_folder,
                             f"ClusterCommand_fetch_{timestamp}.csv")

    all_fetch_results = []
    cpu_count = os.cpu_count() or 1
    num_workers = max(cpu_count - 1, 1)
    print(f"Starting run on {len(servers)} servers...")

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        futures = {
            pool.submit(execute_plan, srv["ip"], srv, defaults): srv["ip"]
            for srv in servers
        }

        with open(logfile, "w") as log_f:
            for future in as_completed(futures):
                ip = futures[future]

                try:
                    log_output, fetch_results = future.result()
                    log_f.write(log_output + "\n\n")
                    all_fetch_results.extend(fetch_results)
                    print(f"[DONE] {ip}")
                except Exception as e:
                    error_msg = (f"=== {ip} - CRITICAL ERROR (THREAD) ==="
                                 f"\nException in thread execution: {e}\n")
                    log_f.write(error_msg + "\n\n")
                    print(f"[FAIL] {ip} (Check log for details)")

    if all_fetch_results:
        print(f"Writing aggregated data to {fetchfile}...")
        with open(fetchfile, "w", newline="") as csv_f:
            writer = csv.writer(csv_f)
            writer.writerow(["SERVER_IP", "FETCHED_DATA"])
            for ip, data in all_fetch_results:
                writer.writerow([ip, data])

    print("\n--- Summary ---")
    print(f"Logs saved to {logfile}")
    if all_fetch_results:
        print(f"Aggregated fetch data saved to {fetchfile}")
    print("-----------------")


if __name__ == "__main__":
    main()
