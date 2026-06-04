import shlex
import uuid
from pathlib import Path
from datetime import datetime
from bitrixprobe.modules.ssh_client import download_remote_file, run_remote_shell
from bitrixprobe.modules.sanitise_filename import safe_filename

"""
Enumerate Bitrix webroot directory and extract relative endpoints.
"""

CHECK_ID = "bitrix.webroot.enum_files"
CHECK_NAME = "Bitrix webroot file enumeration"

DEPENDS_ON = []
REQUIRES_DETECTED = []

# Remove the remote webroot prefix from each discovered path
# and convert absolute filesystem paths into relative web paths.
def make_relative_webroot_listing(input_path, output_path, webroot) -> int:

    webroot = webroot.rstrip("/")
    entries_count = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as input_file, \
         output_path.open("w", encoding="utf-8") as output_file:

        for line in input_file:
            full_path = line.strip()

            if not full_path:
                continue

            if full_path == webroot:
                continue

            prefix = webroot + "/"

            if full_path.startswith(prefix):
                relative_path = full_path.removeprefix(prefix)
            else:
                relative_path = full_path

            if not relative_path:
                continue

            output_file.write(relative_path + "\n")
            entries_count += 1

    return entries_count


def run(client, audit_config, ssh_config, context) -> dict:
    # Initialize a standard result dictionary for this audit check.
    result = {
        "exit_code": 1,
        "status": "error",
        "detected": False,
        "stdout": "",
        "stderr": "",
    }

    webroot = audit_config["webroot"].rstrip("/")
    output_dir = Path(audit_config.get("output_dir", "reports"))

    ssh_host = ssh_config.get("ssh_host", "unknown_host")
    safe_host = safe_filename(ssh_host)
    safe_webroot = safe_filename(webroot.strip("/") or "webroot")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate a random unique identifier for this check run.
    # It is used in temporary filenames to prevent collisions.
    scan_id = uuid.uuid4().hex

    remote_tmp_dir = "/tmp/bitrixprobe"
    remote_listing_path = f"{remote_tmp_dir}/webroot_listing_{scan_id}.txt"
    remote_error_path = f"{remote_tmp_dir}/webroot_listing_{scan_id}.err"

    local_absolute_listing_path = (
        output_dir / f"webroot_absolute_{safe_webroot}_{safe_host}_{timestamp}.txt"
    )

    local_relative_listing_path = (
        output_dir / f"webroot_relative_{safe_webroot}_{safe_host}_{timestamp}.txt"
    )

    local_error_path = (
        output_dir / f"webroot_errors_{safe_webroot}_{safe_host}_{timestamp}.err"
    )

    quoted_webroot = shlex.quote(webroot)
    quoted_remote_tmp_dir = shlex.quote(remote_tmp_dir)
    quoted_remote_listing_path = shlex.quote(remote_listing_path)
    quoted_remote_error_path = shlex.quote(remote_error_path)

    prepare_tmp_dir_command = (
        f"mkdir -p {quoted_remote_tmp_dir} && "
        f"chmod 700 {quoted_remote_tmp_dir}"
    )

    prepare_result = run_remote_shell(client, prepare_tmp_dir_command)

    if prepare_result["exit_code"] != 0:
        result["exit_code"] = prepare_result["exit_code"]
        result["status"] = "error"
        result["detected"] = False
        result["stdout"] = ""
        result["stderr"] = (
            "Failed to prepare remote temporary directory.\n"
            + prepare_result["stderr"]
        )

        return result

    command = (
        f"find {quoted_webroot} "
        f"\\( -type f -o -type d \\) "
        f"-print > {quoted_remote_listing_path} "
        f"2> {quoted_remote_error_path}"
    )

    find_result = run_remote_shell(client, command)

    has_error_file = False
    relative_entries_count = 0

    try:
        download_remote_file(
            client=client,
            remote_path=remote_listing_path,
            local_path=local_absolute_listing_path,
        )

        relative_entries_count = make_relative_webroot_listing(
            input_path=local_absolute_listing_path,
            output_path=local_relative_listing_path,
            webroot=webroot,
        )

        error_stat = run_remote_shell(
            client,
            f"test -s {quoted_remote_error_path}"
        )

        has_error_file = error_stat["exit_code"] == 0

        if has_error_file:
            download_remote_file(
                client=client,
                remote_path=remote_error_path,
                local_path=local_error_path,
            )

    finally:
        cleanup_command = (
            f"rm -f {quoted_remote_listing_path} "
            f"{quoted_remote_error_path} && "
            f"rmdir {quoted_remote_tmp_dir} 2>/dev/null || true"
        )

        run_remote_shell(client, cleanup_command)

    stdout = (
        f"Webroot recursive listing completed.\n"
        f"Remote webroot: {webroot}\n"
        f"Absolute listing file: {local_absolute_listing_path}\n"
        f"Relative listing file: {local_relative_listing_path}\n"
        f"Relative entries count: {relative_entries_count}"
    )

    if has_error_file:
        stdout += f"\nError file: {local_error_path}"

    if find_result["exit_code"] != 0:
        stdout += (
            "\nFind command finished with non-zero exit code. "
            "Some paths may be inaccessible. Check the error file if it was created."
        )

    # Add context
    if "bitrix" not in context:
        context["bitrix"] = {}
    context["bitrix"]["webroot_files"] = {
        "webroot": webroot,
        "absolute_listing_file": str(local_absolute_listing_path),
        "relative_listing_file": str(local_relative_listing_path),
        "error_file": str(local_error_path) if has_error_file else "",
        "relative_entries_count": relative_entries_count,
    }

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = relative_entries_count > 0
    result["stdout"] = stdout
    result["stderr"] = find_result["stderr"].strip()

    return result