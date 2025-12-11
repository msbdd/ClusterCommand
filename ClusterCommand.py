import paramiko
import yaml
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import csv
import contextlib
import os


def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def ssh_connect(
    ip, username, key_filename=None, password=None, policy="reject"
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
            timeout=10,
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


def execute_plan(ip, config, defaults):
    final_config = defaults.copy()
    final_config.update(config)

    username = final_config["username"]
    key_filename = final_config.get("key_filename")
    password = final_config.get("password")

    host_key_policy = final_config.get("host_key_policy", "reject")

    commands = final_config.get("commands", [])

    log = [
        f"=== {ip} - START: {datetime.datetime.now().strftime('%H:%M:%S')} ==="
    ]
    fetch_data = []

    if not key_filename and not password:
        log.append(
            f"[ERROR] No 'key_filename' or 'password'"
            f" provided for {ip}. Skipping."
        )
        return "\n".join(log), fetch_data

    try:

        client = ssh_connect(
            ip,
            username,
            key_filename=key_filename,
            password=password,
            policy=host_key_policy,
        )
    except ConnectionError as e:
        log.append(f"[ERROR] SSH connection failed: {e}")
        return "\n".join(log), fetch_data
    except Exception as e:
        log.append(f"[ERROR] Unexpected connection error: {e}")
        return "\n".join(log), fetch_data

    with client:
        for step in commands:
            step_type = step["type"]

            if step_type == "upload":
                local = step["local"]
                remote = step["remote"]
                try:
                    upload_file(client, local, remote)
                    log.append(f"[UPLOAD OK] {local} → {remote}")
                except Exception as e:
                    log.append(f"[UPLOAD ERROR] Failed to upload {local}: {e}")
                    return "\n".join(log), fetch_data

            elif step_type == "run" or step_type == "fetch":
                cmd = step["cmd"]
                log.append(f"\n> {cmd}")

                out, err, code = run_ssh_command(client, cmd)
                log.append(out.strip())
                if err:
                    log.append("ERR: " + err.strip())

                if "expect_exit" in step and code != step["expect_exit"]:
                    log.append(
                        f"[ERROR] Unexpected exit code {code}."
                        f" Expected {step['expect_exit']}"
                    )
                    return "\n".join(log), fetch_data

                if "expect" in step:
                    expected = step.get("expect", "")

                    if expected not in out:
                        log.append("[ERROR] Expected output missing.")
                        log.append(f"Missing: {expected}")
                        return "\n".join(log), fetch_data

                if step_type == "fetch":
                    lines = out.strip().splitlines()
                    for line in lines:
                        if line.strip():
                            fetch_data.append((ip, line.strip()))

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
    num_workers = max(os.cpu_count()-1, 1) or 1
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
