import shlex
from bitrixprobe.console import red, yellow
from bitrixprobe.modules.ssh_client import run_remote_shell

"""
Detect Bitrix restore.php files left in the webroot.
"""


CHECK_ID = "bitrix.restore.detect"
CHECK_NAME = "Detect Bitrix restore.php exposure"

DEPENDS_ON = []
REQUIRES_DETECTED = []

REFERENCE_RESTORE_MD5 = "e0a6e01f7851072006d5fb5fe61e854a"

SHALLOW_SCAN_DIRS = [
    "",
    "tmp",
    "bitrix/tmp",
    "bitrix",
    "bitrix/upload",
    "upload",
    "bitrix/backup",
    "backup",
    "1",
    "log",
    "bitrix/log",
]

RESTORE_MARKERS = [
    '"BASE_RESTORE" => "Восстановить"',
    '"BASE_RESTORE" => "Wiederherstellen"',
    '"BASE_RESTORE" => "Restore"',
    "class CDBRestore",
    "class CTarRestore",
    "RESTORE_FILE_LIST",
    "this script must be started from Web Server's DOCUMENT ROOT",
]


def build_scan_dirs(webroot) -> list:
    """
    Build a unique list of scan directories from the webroot.
    """

    webroot = webroot.rstrip("/")
    scan_dirs = []

    for relative_dir in SHALLOW_SCAN_DIRS:
        if relative_dir:
            scan_dir = f"{webroot}/{relative_dir}"
        else:
            scan_dir = webroot

        if scan_dir not in scan_dirs:
            scan_dirs.append(scan_dir)

    return scan_dirs


def build_restore_scan_command(webroot) -> str:
    """
    Build a remote shell command that detects restore.php files and signatures.
    """

    quoted_webroot = shlex.quote(webroot.rstrip("/"))
    quoted_reference_md5 = shlex.quote(REFERENCE_RESTORE_MD5)
    quoted_scan_dirs = " ".join(
        shlex.quote(scan_dir) for scan_dir in build_scan_dirs(webroot)
    )

    marker_checks = []

    for marker in RESTORE_MARKERS:
        quoted_marker = shlex.quote(marker)
        marker_checks.append(
            f"""
    if grep -aFq {quoted_marker} "$file_path" 2>/dev/null; then
        reasons="${{reasons}},marker"

        if [ -z "$markers" ]; then
            markers={quoted_marker}
        else
            markers="${{markers}} | "{quoted_marker}
        fi
    fi
""".rstrip()
        )

    marker_checks_script = "\n".join(marker_checks)

    return f"""
webroot={quoted_webroot}
reference_md5={quoted_reference_md5}

calc_md5() {{
    file_path="$1"

    if command -v md5sum >/dev/null 2>&1; then
        md5sum "$file_path" 2>/dev/null | awk '{{print $1}}'
        return
    fi

    if command -v md5 >/dev/null 2>&1; then
        md5 -q "$file_path" 2>/dev/null
        return
    fi

    if command -v openssl >/dev/null 2>&1; then
        openssl dgst -md5 "$file_path" 2>/dev/null | awk '{{print $NF}}'
        return
    fi

    printf '%s' '-'
}}

print_candidates() {{

    for scan_dir in {quoted_scan_dirs}; do
        [ -d "$scan_dir" ] || continue
        find "$scan_dir" -maxdepth 1 -type f -print 2>/dev/null
    done
}}

print_candidates | sort -u | while IFS= read -r file_path; do
    [ -f "$file_path" ] || continue

    file_name=$(basename "$file_path")
    file_size=$(wc -c < "$file_path" 2>/dev/null | tr -d ' ')
    file_md5=$(calc_md5 "$file_path")

    reasons=""
    markers=""

    if [ "$file_name" = "restore.php" ]; then
        reasons="${{reasons}},name"
    fi

    if [ "$file_md5" = "$reference_md5" ]; then
        reasons="${{reasons}},md5"
    fi

{marker_checks_script}

    if [ -n "$reasons" ]; then
        reasons=$(printf '%s' "$reasons" | sed 's/^,//')
        printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "$file_path" "$file_md5" "$file_size" "$reasons" "$markers"
    fi
done
""".strip()


def parse_restore_scan_output(output) -> list:
    """
    Parse tab-separated restore scan output from the remote shell.
    """

    findings = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split("\t")

        if len(parts) < 4:
            continue

        while len(parts) < 5:
            parts.append("")

        path, md5_hash, size, reasons, markers = parts[:5]

        findings.append(
            {
                "path": path,
                "md5": md5_hash,
                "size": size,
                "reasons": [item for item in reasons.split(",") if item],
                "markers": [
                    item.strip()
                    for item in markers.split("|")
                    if item.strip()
                ],
            }
        )

    return findings


def format_reason(reasons) -> str:
    """
    Format restore detection reasons for stdout.
    """

    if not reasons:
        return "-"

    labels = {
        "name": "filename restore.php",
        "md5": "reference MD5",
        "marker": "restore.php content marker",
    }

    formatted_reasons = []

    for reason in reasons:
        formatted_reasons.append(labels.get(reason, reason))

    return ", ".join(formatted_reasons)


def format_findings(findings) -> str:
    """
    Format restore.php findings for terminal and report output.
    """

    if not findings:
        return "-"

    lines = []

    for finding in findings:
        lines.append(f"- Path: {finding.get('path', '-')}")
        lines.append(f"  MD5: {finding.get('md5', '-')}")
        lines.append(f"  Size: {finding.get('size', '-')} bytes")
        #lines.append(f"  Matched by: {format_reason(finding.get('reasons', []))}")

        markers = finding.get("markers", [])

        if markers:
            lines.append("  Matched markers:")

            for marker in markers:
                lines.append(f"    - {marker}")

    return "\n".join(lines)


def run(client, audit_config, ssh_config, context) -> dict:
    """
    Search selected remote webroot directories for restore.php files.
    """

    result = {
        "exit_code": 1,
        "status": "error",
        "detected": False,
        "stdout": "",
        "stderr": "",
    }

    webroot = audit_config.get("webroot", "").rstrip("/")

    if not webroot:
        result["stderr"] = "Missing audit_config webroot."

        return result

    command = build_restore_scan_command(webroot)
    scan_result = run_remote_shell(client, command)

    if scan_result["exit_code"] != 0:
        result["exit_code"] = scan_result["exit_code"]
        result["status"] = "error"
        result["detected"] = False
        result["stderr"] = scan_result["stderr"].strip()

        return result

    findings = parse_restore_scan_output(scan_result["stdout"])
    detected = len(findings) > 0

    if "bitrix" not in context:
        context["bitrix"] = {}

    context["bitrix"]["restore_php"] = {
        "detected": detected,
        "webroot": webroot,
        "reference_md5": REFERENCE_RESTORE_MD5,
        "scan_dirs": build_scan_dirs(webroot),
        "findings": findings,
        "stderr": scan_result["stderr"].strip(),
    }

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = detected

    if detected:
        result["stdout"] = (
            f"{red('[!] Possible [File Upload + RCE] vulnerability, found restore.php file, double check and remove it!')}\n"
            f"Remote webroot: {webroot}\n"
            f"Findings count: {len(findings)}\n\n"
            f"{format_findings(findings)}"
        )
    else:
        result["stdout"] = (
            "Bitrix restore.php file was not detected.\n"
            f"Remote webroot: {webroot}\n"
            f"Reference restore.php MD5: {REFERENCE_RESTORE_MD5}\n"
            f"{yellow('Note')}: shallow scan checks known directories "
            "by filename, MD5, and content markers."
        )

    result["stderr"] = scan_result["stderr"].strip()

    return result
