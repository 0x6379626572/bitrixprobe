import socket
import paramiko
from pathlib import Path
import shlex

#TODO: Add key auth

def connect_ssh(config, timeout=10):
    client = paramiko.SSHClient()

    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy()) # Warn about the abscent key but allow connection

    try:
        client.connect(
            hostname=config["ssh_host"],
            port=config["ssh_port"],
            username=config["ssh_user"],
            password=config["ssh_password"],
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        return client

    except paramiko.AuthenticationException as error:
        raise RuntimeError("SSH authentication failed.") from error

    except paramiko.SSHException as error:
        raise RuntimeError(f"SSH connection error: {error}") from error

    except socket.timeout as error:
        raise RuntimeError("SSH connection timeout.") from error

    except OSError as error:
        raise RuntimeError(f"Network error during SSH connection: {error}") from error


def run_remote_shell(client, command, shell="/bin/sh"):
    """
    Execute a remote command through a predictable shell wrapper.
    A controlled PATH helps the scanner find common administrative binaries
    even when the non-interactive SSH session has a minimal environment.
    LC_ALL=C forces stable English command output where possible, which makes
    parsing and detection logic more predictable.
    """
    safe_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    wrapped_script = (
        f"export PATH={shlex.quote(safe_path)}; "
        f"export LC_ALL=C; "
        f"{command}"
    )

    quoted_script = shlex.quote(wrapped_script)
    wrapped_command = f"{shell} -c {quoted_script}"

    return run_ssh_command(client, wrapped_command)


def run_ssh_command(client, command) -> dict:
    stdin, stdout, stderr = client.exec_command(command)

    exit_code = stdout.channel.recv_exit_status()

    stdout_text = stdout.read().decode("utf-8", errors="replace")
    stderr_text = stderr.read().decode("utf-8", errors="replace")

    return {
        "exit_code": exit_code,
        "stdout": stdout_text,
        "stderr": stderr_text,
    }


def download_remote_file(client, remote_path, local_path) -> Path:
    # Download remote file over sft

    local_path = Path(local_path)
    local_path.parent.mkdir(parents=True, exist_ok=True)

    sftp = client.open_sftp()

    try:
        sftp.get(str(remote_path), str(local_path))
    finally:
        sftp.close()

    return local_path


def remove_remote_file(client, remote_path):
    # Remove remote file over sft

    sftp = client.open_sftp()

    try:
        sftp.remove(str(remote_path))
    finally:
        sftp.close()