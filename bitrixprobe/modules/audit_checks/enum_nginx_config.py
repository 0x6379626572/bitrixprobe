import re
from bitrixprobe.modules.ssh_client import run_remote_shell


"""
Enumerate Nginx HTTP Server configuration and extract useful paths.
"""


CHECK_ID = "webserver.nginx.enum_config"
CHECK_NAME = "Enumerate Nginx configuration"

DEPENDS_ON = ["webserver.nginx.detect"]
REQUIRES_DETECTED = ["webserver.nginx.detect"]


def run_nginx_config_probe(client, title, command) -> dict:
    """
    Run a single Nginx configuration enumeration probe.
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


def extract_nginx_roots(root_output) -> list:
    """
    Extract Nginx root directive values from grep output.
    Expected input line example:
    /etc/nginx/sites-enabled/site.conf:12:root /var/www/html;
    """

    webroots = []

    for line in root_output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split(":", 2)

        if len(parts) != 3:
            continue

        directive = parts[2].strip()

        match = re.match(
            r"^root[ \t]+(.+)$",
            directive,
            flags=re.IGNORECASE,
        )

        if not match:
            continue

        webroot = match.group(1).strip()

        if "#" in webroot:
            webroot = webroot.split("#", 1)[0].strip()

        webroot = webroot.rstrip(";").strip()
        webroot = webroot.strip('"').strip("'")

        if webroot and webroot not in webroots:
            webroots.append(webroot)

    return webroots


def extract_nginx_aliases(alias_output) -> list:
    """
    Extract Nginx alias directive values from grep output.
    Expected input line example:
    /etc/nginx/sites-enabled/site.conf:20:alias /var/www/static/;
    """

    aliases = []

    for line in alias_output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split(":", 2)

        if len(parts) != 3:
            continue

        directive = parts[2].strip()

        match = re.match(
            r"^alias[ \t]+(.+)$",
            directive,
            flags=re.IGNORECASE,
        )

        if not match:
            continue

        alias_path = match.group(1).strip()

        if "#" in alias_path:
            alias_path = alias_path.split("#", 1)[0].strip()

        alias_path = alias_path.rstrip(";").strip()
        alias_path = alias_path.strip('"').strip("'")

        if alias_path and alias_path not in aliases:
            aliases.append(alias_path)

    return aliases


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
            "title": "Nginx Config Files",
            "command": r"""
for file in \
    /etc/nginx/nginx.conf \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -f "$file" ]; then
        echo "$file"
    fi
done

for dir in \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled
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
            "title": "Nginx active root locations",
            "command": r"""
for path in \
    /etc/nginx/nginx.conf \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -e "$path" ]; then
        grep -RInE '^[[:space:]]*root[[:space:]]+' "$path" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "alias_paths",
            "title": "Nginx alias locations",
            "command": r"""
for path in \
    /etc/nginx/nginx.conf \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -e "$path" ]; then
        grep -RInE '^[[:space:]]*alias[[:space:]]+' "$path" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "vhost_summary",
            "title": "Nginx Virtual Hosts",
            "command": r"""
for path in \
    /etc/nginx/nginx.conf \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -e "$path" ]; then
        grep -RInE '^[[:space:]]*server_name[[:space:]]+' "$path" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "listen_ports",
            "title": "Nginx Listen Ports",
            "command": r"""
for path in \
    /etc/nginx/nginx.conf \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -e "$path" ]; then
        grep -RInE '^[[:space:]]*listen[[:space:]]+' "$path" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "server_names",
            "title": "Nginx ServerNames",
            "command": r"""
for path in \
    /etc/nginx/nginx.conf \
    /etc/nginx/conf.d \
    /etc/nginx/sites-enabled \
    /usr/local/nginx/conf/nginx.conf \
    /opt/nginx/conf/nginx.conf
do
    if [ -e "$path" ]; then
        grep -RInE '^[[:space:]]*server_name[[:space:]]+' "$path" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "include_directives",
            "title": "Nginx Include Configs",
            "command": r"""
for dir in \
    /etc/nginx \
    /usr/local/nginx/conf \
    /opt/nginx/conf
do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*include[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "log_paths",
            "title": "Nginx Log Paths",
            "command": r"""
for dir in \
    /etc/nginx \
    /usr/local/nginx/conf \
    /opt/nginx/conf
do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*(access_log|error_log)[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done \
| sed -E 's|^[^:]+:[0-9]+:[[:space:]]*||' \
| awk '
{
    if (!seen[$0]++) {
        print
    }
}
'
""",
        },
        {
            "key": "ssl_certificates",
            "title": "Nginx SSL certificates",
            "command": r"""
for dir in \
    /etc/nginx \
    /usr/local/nginx/conf \
    /opt/nginx/conf
do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "php_proxy_handlers",
            "title": "Nginx PHP and proxy handlers",
            "command": r"""
for dir in \
    /etc/nginx \
    /usr/local/nginx/conf \
    /opt/nginx/conf
do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*[^#].*(fastcgi_pass|proxy_pass|uwsgi_pass|scgi_pass|php-fpm|\.php|try_files)' "$dir" 2>/dev/null || true
    fi
done | sed -E 's/^([^:]+:[0-9]+:)[[:space:]]*/\1/'
""",
        },
        {
            "key": "active_modules",
            "title": "Nginx active modules",
            "command": r"""
echo "[Load module directives]"
for dir in \
    /etc/nginx \
    /usr/local/nginx/conf \
    /opt/nginx/conf
do
    if [ -d "$dir" ]; then
        grep -RInE '^[[:space:]]*load_module[[:space:]]+' "$dir" 2>/dev/null || true
    fi
done

echo
echo "[Nginx build options]"
nginx -V 2>&1 | tr ' ' '\n' | grep -E '^--(with|add)-' || true

echo
echo "[Known dynamic module files]"
for dir in \
    /usr/lib/nginx/modules \
    /usr/share/nginx/modules \
    /etc/nginx/modules-enabled
do
    if [ -d "$dir" ]; then
        find -L "$dir" -maxdepth 1 \
            -name "*.so" \
            -print 2>/dev/null || true
    fi
done
""",
        },
    ]

    probe_results = {}
    stdout_sections = []
    stderr_parts = []

    for probe in probes:
        probe_result = run_nginx_config_probe(
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

    root_lines = probe_results["document_roots"]["stdout"]
    alias_lines = probe_results["alias_paths"]["stdout"]

    webroots = extract_nginx_roots(root_lines)
    alias_paths = extract_nginx_aliases(alias_lines)

    detected = bool(config_paths or webroots or alias_paths)

    if "webservers" not in context:
        context["webservers"] = {}

    if "nginx" not in context["webservers"]:
        context["webservers"]["nginx"] = {}

    context["webservers"]["nginx"]["config_paths"] = config_paths
    context["webservers"]["nginx"]["webroots"] = webroots
    context["webservers"]["nginx"]["alias_paths"] = alias_paths
    context["webservers"]["nginx"]["config_probes"] = probe_results
    context["webservers"]["nginx"]["active_modules"] = active_modules

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = detected
    result["stdout"] = "\n\n".join(stdout_sections)
    result["stderr"] = "\n\n".join(stderr_parts)

    return result