import argparse
import getpass
import os
import stat
import sys
from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import urlparse

# Check for proper security permission
REQUIRED_ENV_MODE = 0o640
def check_env_file_permissions(env_path) -> bool:
    path = Path(env_path)

    if not path.exists():
        return False

    if path.is_symlink():
        raise PermissionError(
            f"{path} must not be a symlink for security reasons."
        )

    current_mode = stat.S_IMODE(path.stat().st_mode) # Extract permission bits of file

    if current_mode != REQUIRED_ENV_MODE:
        raise PermissionError(
            f"Wrong permissions for {path}: {oct(current_mode)}. "
            f"Expected: {oct(REQUIRED_ENV_MODE)}. "
            f"Fix it with: chmod 640 {path}"
        )

    return True


def check_port(value) -> int | None:
    """
    Validate and normalize a TCP port value.
    """

    if value is None or value == "":
        return None

    try:
        ssh_port = int(value)
    except ValueError:
        raise ValueError(f"Invalid  port: {value}")

    if ssh_port < 1 or ssh_port > 65535:
        raise ValueError(f"Port must be between 1 and 65535: {ssh_port}")

    return ssh_port


def get_schemeless_default_scheme(target_url) -> str:
    """
    Return the default scheme for a target URL that has no explicit scheme.
    """

    parsed_url = urlparse(f"//{target_url}")

    try:
        port = parsed_url.port
    except ValueError as error:
        raise ValueError(f"Invalid target port in URL: {target_url}") from error

    if port == 80:
        return "http"

    return "https"


def parse_pentest_target(target_url) -> dict:
    """
    Parse and normalize pentest target URL.

    Examples:
    - example.com -> https://example.com
    - example.com:9999 -> https://example.com:9999
    - http://example.com -> http://example.com
    - https://example.com:9999 -> https://example.com:9999
    """

    if target_url is None:
        raise ValueError("Target URL is empty.")

    original_url = target_url.strip()

    if not original_url:
        raise ValueError("Target URL is empty.")

    normalized_url = original_url
    scheme_was_missing = "://" not in normalized_url

    if scheme_was_missing:
        default_scheme = get_schemeless_default_scheme(normalized_url)
        normalized_url = f"{default_scheme}://{normalized_url}"

    parsed_url = urlparse(normalized_url)

    scheme = parsed_url.scheme.lower()

    if scheme != "http" and scheme != "https":
        raise ValueError(f"Unsupported URL scheme: {scheme}")

    host = parsed_url.hostname

    if not host:
        raise ValueError(f"Target host is empty: {original_url}")

    explicit_port = False
    port = None

    try:
        port = parsed_url.port
    except ValueError as error:
        raise ValueError(f"Invalid target port in URL: {original_url}") from error

    if port:
        explicit_port = True
    else:
        if scheme == "https":
            port = 443
        else:
            port = 80

    port = check_port(port)

    path = parsed_url.path

    if path == "/":
        path = ""

    if path:
        path = path.rstrip("/")

    display_host = host

    if ":" in host and not host.startswith("["):
        display_host = f"[{host}]"

    default_https_port = False
    default_http_port = False
    if scheme == "https" and port == 443:
        default_https_port = True
    if scheme == "http" and port == 80:
        default_http_port = True

    if explicit_port:
        netloc = f"{display_host}:{port}"
    elif default_https_port or default_http_port:
        netloc = display_host
    else:
        netloc = f"{display_host}:{port}"

    url = f"{scheme}://{netloc}"

    if path:
        url = f"{url}{path}"

    return {
        "original_url": original_url,
        "url": url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "netloc": netloc,
        "path": path,
        "explicit_port": explicit_port,
        "scheme_was_missing": scheme_was_missing,
    }


def build_pentest_config(args) -> dict:
    """
    Build pentest configuration from CLI arguments.
    """

    target = parse_pentest_target(args.url)

    return {
        "target": target,
    }




def load_env_config(env_path) -> dict:
    env_exists = check_env_file_permissions(env_path)

    if not env_exists:
        return {
            "ssh_host": None,
            "ssh_port": None,
            "ssh_user": None,
            "ssh_password": None,
            "webroot": None
        }

    load_dotenv(dotenv_path=env_path)

    return {
        "ssh_host": os.getenv("BP_SSH_HOST"),
        "ssh_port": check_port(os.getenv("BP_SSH_PORT")),
        "ssh_user": os.getenv("BP_SSH_USER"),
        "ssh_password": os.getenv("BP_SSH_PASSWORD"),
        "webroot": os.getenv("BP_WEBROOT"),
    }


def add_ssh_arguments(parser):
    parser.add_argument(
        "-H",
        "--host",
        help="SSH server address"
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="SSH server port"
    )

    parser.add_argument(
        "-u",
        "--user",
        help="SSH username"
    )

    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file. Default: .env"
    )

    parser.add_argument(
        "--webroot",
        help="Remote webroot directory, for example: /var/www/bitrix"
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Local directory for report files"
    )


def parse_args(argv=None) -> argparse.Namespace:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="bitrixprobe",
        description="BitrixProbe vulnerability assessment tool for Bitrix CMS",
        epilog=(
            "Examples:\n"
            "  bitrixprobe audit --host 192.168.56.10 --port 22 --user auditor --webroot /var/www/bitrix\n"
            "  bitrixprobe pentest --url http://192.168.56.10\n"
            "  bitrixprobe pentest --url bitrix.local\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(
        dest="mode",
        required=True
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Run local server audit over SSH"
    )
    add_ssh_arguments(audit_parser)

    pentest_parser = subparsers.add_parser(
        "pentest",
        help="Run external Bitrix checks"
    )

    pentest_parser.add_argument(
        "--url",
        required=True,
        help=(
            "Target URL or FQDN, for example: example.com, bitrix.local, "
            "https://example.com, or https://192.168.56.10:8080"
        )
    )

    if not argv:
        parser.print_help()
        raise SystemExit(0)

    return parser.parse_args(argv)


def ask_user_for_missing_ssh_config(config) -> dict:
    if not config.get("ssh_host"):
        config["ssh_host"] = input("SSH host: ").strip()

    if not config.get("ssh_port"):
        raw_port = input("SSH port [22]: ").strip()
        if raw_port:
            config["ssh_port"] = check_port(raw_port)
        else:
            config["ssh_port"] = 22

    if not config.get("ssh_user"):
        config["ssh_user"] = input("SSH username: ").strip()

    if not config.get("ssh_password"):
        config["ssh_password"] = getpass.getpass("SSH password: ")

    return config

def build_audit_config(args) -> dict:
    env_config = load_env_config(args.env_file)

    webroot = args.webroot or env_config.get("webroot")

    if not webroot:
        raise ValueError(
            "Missing required webroot. Use --webroot or set BP_WEBROOT in .env."
        )

    return {
        "webroot": webroot.rstrip("/"),
        "output_dir": args.output_dir,
    }

def build_ssh_config(args) -> dict:
    env_config = load_env_config(args.env_file)

    config = {
        "ssh_host": args.host or env_config.get("ssh_host"),
        "ssh_port": args.port or env_config.get("ssh_port") or 22,
        "ssh_user": args.user or env_config.get("ssh_user"),
        "ssh_password": env_config.get("ssh_password"),

    }

    config = ask_user_for_missing_ssh_config(config)

    return config
