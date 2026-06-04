from bitrixprobe.modules.ssh_client import run_remote_shell

"""
Detect Apache HTTP Server on the remote host.

Apache running processes 
Apache binaries 
Apache systemd services 
Apache config paths 
Apache packages 
Apache version

context["webservers"]["apache"]["probes"]["config_paths"]["stdout"]
"""

CHECK_ID = "webserver.apache.detect"
CHECK_NAME = "Detect Apache HTTP Server"

DEPENDS_ON = []
REQUIRES_DETECTED = []

def run_apache_probe(client, title, command) -> dict:
    """
    Run a single Apache detection probe and return its normalized result.
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
            "title": "Apache running processes",
            "command": r"""
ps -eo pid,user,args | grep -E '[a]pache2|[h]ttpd' || true
""",
        },
        {
            "key": "binaries",
            "title": "Apache binaries",
            "command": r"""
for binary in apache2 httpd apachectl apache2ctl; do
    if command -v "$binary" >/dev/null 2>&1; then
        command -v "$binary"
    fi
done
""",
        },
        {
            "key": "systemd_services",
            "title": "Apache systemd services",
            "command": r"""
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files 2>/dev/null | grep -E '^(apache2|httpd)\.service' || true

    apache2_state="$(systemctl is-active apache2 2>/dev/null || true)"
    httpd_state="$(systemctl is-active httpd 2>/dev/null || true)"

    if [ -n "$apache2_state" ] && [ "$apache2_state" != "unknown" ]; then
        echo "apache2.service: $apache2_state"
    fi

    if [ -n "$httpd_state" ] && [ "$httpd_state" != "unknown" ]; then
        echo "httpd.service: $httpd_state"
    fi
fi
""",
        },
        {
            "key": "config_paths",
            "title": "Apache config paths",
            "command": r"""
for path in \
    /etc/apache2/apache2.conf \
    /etc/apache2/sites-enabled \
    /etc/apache2/sites-available \
    /etc/apache2/conf-enabled \
    /etc/httpd/conf/httpd.conf \
    /etc/httpd/conf.d
do
    if [ -e "$path" ]; then
        echo "$path"
    fi
done
""",
        },
        {
            "key": "packages",
            "title": "Apache packages",
            "command": r"""
if command -v dpkg >/dev/null 2>&1; then
    dpkg -l 2>/dev/null | grep -E '^ii[[:space:]]+(apache2|apache2-bin|apache2-utils)' || true
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa 2>/dev/null | grep -Ei '^(httpd|apache)' || true
fi
""",
        },
        {
            "key": "version",
            "title": "Apache version",
            "command": r"""
apache2 -v 2>/dev/null || httpd -v 2>/dev/null || apachectl -v 2>/dev/null || apache2ctl -v 2>/dev/null || true
""",
        },
    ]

    probe_results = {}
    stdout_sections = []
    stderr_parts = []

    for probe in probes:
        probe_result = run_apache_probe(
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

    apache_detected = False

    for probe_result in probe_results.values():
        if probe_result["detected"]:
            apache_detected = True
            break

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = apache_detected
    result["stdout"] = "\n\n".join(stdout_sections)
    result["stderr"] = "\n\n".join(stderr_parts)

    if "webservers" not in context:
        context["webservers"] = {}

    context["webservers"]["apache"] = {
        "detected": apache_detected,
        "probes": probe_results,
        "raw_output": result["stdout"],
        "config_paths": [],
    }

    return result