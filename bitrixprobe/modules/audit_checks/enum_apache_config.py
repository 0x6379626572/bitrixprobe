import re
from bitrixprobe.modules.ssh_client import run_remote_shell


"""
Enumerate Apache HTTP Server configuration and extract useful paths.
"""


CHECK_ID = "webserver.apache.enum_config"
CHECK_NAME = "Enumerate Apache configuration"

DEPENDS_ON = ["webserver.apache.detect"]
REQUIRES_DETECTED = ["webserver.apache.detect"]


def run_apache_config_probe(client, title, command) -> dict:
    """
    Run a single Apache configuration enumeration probe.
    """

    probe_result = run_remote_shell(client, command)

    return {
        "title": title,
        "exit_code": probe_result["exit_code"],
        "stdout": probe_result["stdout"].strip(),
        "stderr": probe_result["stderr"].strip(),
    }


def parse_lines(output) -> list:
    """
    Convert command output into a clean list of non-empty lines.
    """

    lines = []

    for line in output.splitlines():
        line = line.strip()

        if line:
            lines.append(line)

    return lines


def extract_document_roots(document_root_output) -> list:
    """
    Extract DocumentRoot values from grep output.
    Expected input line example:
    /etc/apache2/sites-enabled/000-default.conf:12:DocumentRoot /var/www/html
    """

    webroots = []

    for line in document_root_output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split(":", 2)

        if len(parts) != 3:
            continue

        directive = parts[2].strip()

        match = re.match(
            r"^DocumentRoot[ \t]+(.+)$",
            directive,
            flags=re.IGNORECASE,
        )

        if not match:
            continue

        webroot = match.group(1).strip()

        if "#" in webroot:
            webroot = webroot.split("#", 1)[0].strip()

        webroot = webroot.strip('"').strip("'")

        if webroot and webroot not in webroots:
            webroots.append(webroot)

    return webroots


def format_probe_output(probe) -> str:
    """
    Format one probe result for human-readable report output.
    """

    lines = []
    lines.append(f"[{probe['title']}]")

    if probe["stdout"]:
        lines.append(probe["stdout"])
    else:
        lines.append("No data found.")

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
            "key": "config_paths",
            "title": "Apache Config Files",
            "command": r"""
        for file in \
            /etc/apache2/apache2.conf \
            /etc/apache2/ports.conf \
            /etc/httpd/conf/httpd.conf
        do
            if [ -f "$file" ]; then
                echo "$file"
            fi
        done

        for dir in \
            /etc/apache2/sites-enabled \
            /etc/httpd/conf.d
        do
            if [ -d "$dir" ]; then
                find -L "$dir" -maxdepth 1 \
                    \( -name "*.conf" \) \
                    -print 2>/dev/null || true
            fi
        done
        """,
        },
        {
            "key": "document_roots",
            "title": "Apache active DocumentRoot Locations",
            "command": r"""
        for path in \
            /etc/apache2/apache2.conf \
            /etc/apache2/ports.conf \
            /etc/apache2/sites-enabled \
            /etc/apache2/conf-enabled \
            /etc/httpd/conf/httpd.conf \
            /etc/httpd/conf.d
        do
            if [ -e "$path" ]; then
                grep -RInE '^[[:space:]]*DocumentRoot[[:space:]]+' "$path" 2>/dev/null || true
            fi
        done
        """,
        },
        {
            "key": "vhost_summary",
            "title": "Apache Virtual Hosts",
            "command": r"""
        if command -v apache2ctl >/dev/null 2>&1; then
            apache2ctl -S 2>&1
        elif command -v apachectl >/dev/null 2>&1; then
            apachectl -S 2>&1
        elif command -v httpd >/dev/null 2>&1; then
            httpd -S 2>&1
        fi | awk '
            /default server/ {
                sub(/^[ \t]+/, "");
                print;
            }

            /namevhost/ {
                sub(/^[ \t]+/, "");
                print;
            }
        '
        """,
        },
        {
            "key": "listen_ports",
            "title": "Apache Listen Ports",
            "command": r"""
        for dir in /etc/apache2 /etc/httpd; do
            if [ -d "$dir" ]; then
                grep -RInE '^[[:space:]]*Listen[[:space:]]+' "$dir" 2>/dev/null || true
            fi
        done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
        """,
        },
        {
            "key": "server_names",
            "title": "Apache ServerNames and ServerAliases",
            "command": r"""
for dir in /etc/apache2 /etc/httpd; do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*(ServerName|ServerAlias)[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done
""",
        },
        {
            "key": "include_directives",
            "title": "Apache Include Configs",
            "command": r"""
for dir in /etc/apache2 /etc/httpd; do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*(Include|IncludeOptional)[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done
""",
        },
        {
            "key": "log_paths",
            "title": "Apache Log Paths",
            "command": r"""
        if [ -f /etc/apache2/envvars ]; then
            . /etc/apache2/envvars
        fi

        APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"

        for dir in /etc/apache2 /etc/httpd; do
            if [ -d "$dir" ]; then
                grep -RInE '^[[:space:]]*(ErrorLog|CustomLog)[[:space:]]+' "$dir" 2>/dev/null || true
            fi
        done \
        | sed -E 's|^[^:]+:[0-9]+:[[:space:]]*||' \
        | awk -v log_dir="$APACHE_LOG_DIR" '
        {
            gsub(/\$\{APACHE_LOG_DIR\}/, log_dir)
            gsub(/\$APACHE_LOG_DIR/, log_dir)

            if (!seen[$0]++) {
                print
            }
        }
        '
        """,
        },
        {
            "key": "ssl_certificates",
            "title": "Apache SSL certificates",
            "command": r"""
for dir in /etc/apache2 /etc/httpd; do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*(SSLCertificateFile|SSLCertificateKeyFile|SSLCertificateChainFile)[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done
""",
        },
        {
            "key": "active_modules",
            "title": "Apache active modules",
            "command": r"""
        echo "[Enabled module load files]"
        if [ -d /etc/apache2/mods-enabled ]; then
            find -L /etc/apache2/mods-enabled -maxdepth 1 \
                -name "*.load" \
                -print 2>/dev/null || true
        fi

        echo
        echo "[LoadModule directives]"
        if [ -d /etc/httpd/conf.modules.d ]; then
            grep -RInE '^[[:space:]]*LoadModule[[:space:]]+' \
                /etc/httpd/conf.modules.d 2>/dev/null || true
        fi

        echo
        echo "[Loaded modules from Apache runtime]"
        apache2ctl -M 2>/dev/null || apachectl -M 2>/dev/null || httpd -M 2>/dev/null || true
        """,
        }
    ]

    probe_results = {}
    stdout_sections = []
    stderr_parts = []

    for probe in probes:
        probe_result = run_apache_config_probe(
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

    config_paths = parse_lines(probe_results["config_paths"]["stdout"])
    active_modules = parse_lines(probe_results["active_modules"]["stdout"])
    document_root_lines = probe_results["document_roots"]["stdout"]
    webroots = extract_document_roots(document_root_lines)

    detected = bool(config_paths or webroots)

    if "webservers" not in context:
        context["webservers"] = {}

    if "apache" not in context["webservers"]:
        context["webservers"]["apache"] = {}

    context["webservers"]["apache"]["config_paths"] = config_paths
    context["webservers"]["apache"]["webroots"] = webroots
    context["webservers"]["apache"]["config_probes"] = probe_results
    context["webservers"]["apache"]["active_modules"] = active_modules

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = detected
    result["stdout"] = "\n\n".join(stdout_sections)
    result["stderr"] = "\n\n".join(stderr_parts)

    return result