# ClusterCommand

ClusterCommand is a simple parallel SSH orchestration tool driven by a YAML
configuration file. It allows you to upload and download files, run commands, and fetch
command output from multiple servers concurrently.

When Ansible is an overkill and manual is too tiring.

![Code style: flake8](https://img.shields.io/badge/Code%20style-flake8-brightgreen)

![ClusterCommand Build Windows](https://github.com/msbdd/ClusterCommand/actions/workflows/ClusterCommandBuildWindows.yml/badge.svg)


## Usage

```bash
executable config.yaml