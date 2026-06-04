from bitrixprobe.modules.ssh_client import run_remote_shell


"""
Detect Nginx HTTP Server on the remote host.

Nginx running processes
Nginx binaries
Nginx systemd services
Nginx config paths
Nginx packages
Nginx version

context["webservers"]["nginx"]["detected"]
context["webservers"]["nginx"]["probes"]
context["webservers"]["nginx"]["config_paths"]["stdout"]
"""


CHECK_ID = "webserver.nginx.detect"
CHECK_NAME = "Detect Nginx HTTP Server"

DEPENDS_ON = []
REQUIRES_DETECTED = []


def run_nginx_probe(client, title, command) -> dict:
    """
    Run a single Nginx detection probe and return its normalized result.
    """

    probe_result = run_remote_shell(client, command)

    stdout = probe_result["stdout"].strip()
    stderr = probe_result["stderr"].strip()

    return {
        "title": title,
        "exit_code": probe_result["exit_code"],
        "detected": bool(stdout),
        "stdout": stdout,
        "stderr": stderr,
    }


def format_probe_output(probe) -> str:
    """
    Format one probe result for human-readable report output.
    """

    lines = []

    lines.append(f"[{probe['title']}]")

    if probe["detected"]:
        lines.append(probe["stdout"])
    else:
        lines.append("Not found.")

    return "\n".join(lines)


def run(client, audit_config, ssh_config, context) -> dict:
    # Initialize a standard result dictionary for this audit check.
    result = {
        "exit_code": 1,
        "status": "error",
        "detected": False,
        "stdout": "",
        "stderr": "",
    }

    probes = [
        {
            "key": "running_processes",
            "title": "Nginx running processes",
            "command": r"""
ps -eo pid,user,args | grep -E '[n]ginx' || true
""",
        },
        {
            "key": "binaries",
            "title": "Nginx binaries",
            "command": r"""
for binary in nginx openresty; do
    if command -v "$binary" >/dev/null 2>&1; then
        command -v "$binary"
    fi
done
""",
        },
        {
            "key": "systemd_services",
            "title": "Nginx systemd services",
            "command": r"""
        if command -v systemctl >/dev/null 2>&1; then
            for unit in nginx.service openresty.service; do
                load_state="$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)"

                if [ "$load_state" = "loaded" ]; then
                    active_state="$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"
                    unit_file_state="$(systemctl show "$unit" -p UnitFileState --value 2>/dev/null || true)"

                    echo "$unit: load=$load_state active=$active_state enabled=$unit_file_state"
                fi
            done
        fi
        """,
        },
        {
            "key": "config_paths",
            "title": "Nginx config paths",
            "command": r"""
for path in \
    /etc/nginx/nginx.conf \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled \
    /etc/nginx/sites-available \
    /etc/nginx/bx \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -e "$path" ]; then
        echo "$path"
    fi
done
""",
        },
        {
            "key": "packages",
            "title": "Nginx packages",
            "command": r"""
if command -v dpkg >/dev/null 2>&1; then
    dpkg -l 2>/dev/null | grep -E '^ii[[:space:]]+(nginx|nginx-common|nginx-core|nginx-full|nginx-extras|openresty)' || true
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa 2>/dev/null | grep -Ei '^(nginx|openresty)' || true
fi
""",
        },
        {
            "key": "version",
            "title": "Nginx version",
            "command": r"""
for binary in nginx openresty; do
    if command -v "$binary" >/dev/null 2>&1; then
        "$binary" -v 2>&1
    fi
done
""",
        },
    ]

    probe_results = {}
    stdout_sections = []
    stderr_parts = []

    for probe in probes:
        probe_result = run_nginx_probe(
            client=client,
            title=probe["title"],
            command=probe["command"],
        )

        probe_results[probe["key"]] = probe_result
        stdout_sections.append(format_probe_output(probe_result))

        if probe_result["stderr"]:
            stderr_parts.append(
                f"[{probe_result['title']}]\n{probe_result['stderr']}"
            )

    nginx_detected = False

    for probe_result in probe_results.values():
        if probe_result["detected"]:
            nginx_detected = True
            break

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = nginx_detected
    result["stdout"] = "\n\n".join(stdout_sections)
    result["stderr"] = "\n\n".join(stderr_parts)

    if "webservers" not in context:
        context["webservers"] = {}

    context["webservers"]["nginx"] = {
        "detected": nginx_detected,
        "probes": probe_results,
        "raw_output": result["stdout"],
        "config_paths": [],
    }

    return result