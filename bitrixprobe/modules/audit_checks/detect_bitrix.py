import re
import shlex
import sqlite3
from pathlib import Path
from bitrixprobe.modules.ssh_client import run_remote_shell
from bitrixprobe.console import green, red, yellow, cyan, bold, blue
import json
import textwrap

"""
Detect Bitrix core version and identify whether the installation looks like
1C-Bitrix Site Management or Bitrix24 On-Premise.

Detect modules, versions and outdated statuses.

Risk: the runtime probe requires PHP to be available on the remote server and a working Bitrix prolog.
If PHP CLI is not available or Bitrix cannot connect to the database, the module will return an error in stderr, 
while directories and versions from disk will still be collected.
/bitrix/modules/main/include/prolog_before.php - is required for Bitrix to run
"""


CHECK_ID = "bitrix.detect"
CHECK_NAME = "Detect Bitrix CMS & Installed Modules"

DEPENDS_ON = []
REQUIRES_DETECTED = []


def run_bitrix_probe(client, title, command) -> dict:
    """
    Run a single Bitrix detection probe and return its normalized result.
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
    Convert command output into a clean list of unique non-empty lines.
    """

    lines = []

    for line in output.splitlines():
        line = line.strip()

        if line and line not in lines:
            lines.append(line)

    return lines


def extract_define_value(output, constant_name) -> str:
    """
    Extract a PHP define() constant value from command output.
    """

    pattern = (
        r"define\(\s*['\"]"
        + re.escape(constant_name)
        + r"['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"
    )

    match = re.search(pattern, output)

    if not match:
        return ""

    return match.group(1).strip()


def classify_bitrix_product(installed_modules) -> dict:
    """
    Classify Bitrix product type based on detected module directories.
    """

    bitrix24_strong_modules = [
        "crm",
        "intranet",
        "tasks",
        "disk",
        "timeman",
        "voximplant",
        "extranet",
        "imopenlines",
        "documentgenerator",
    ]

    bitrix24_medium_modules = [
        "crm",
        "intranet",
        "tasks",
    ]

    common_module_candidates = [
        "main",
        "iblock",
        "fileman",
        "sale",
        "catalog",
        "search",
        "seo",
    ]

    bitrix24_modules = []

    for module_name in bitrix24_strong_modules:
        if module_name in installed_modules:
            bitrix24_modules.append(module_name)

    common_modules = []

    for module_name in common_module_candidates:
        if module_name in installed_modules:
            common_modules.append(module_name)

    product_guess = "bitrix_framework_unknown"
    confidence = "low"

    if len(bitrix24_modules) >= 3:
        product_guess = "Bitrix24"
        confidence = "high"
    else:
        for module_name in bitrix24_medium_modules:
            if module_name in installed_modules:
                product_guess = "Bitrix24"
                confidence = "medium"
                break

    if product_guess == "bitrix_framework_unknown":
        has_common_modules = True

        for module_name in common_module_candidates:
            if module_name not in installed_modules:
                has_common_modules = False
                break

        if has_common_modules:
            product_guess = "1C-Bitrix Site Management"
            confidence = "medium"
        elif common_modules:
            product_guess = "1C-Bitrix Site Management"
            confidence = "low"

    return {
        "product_guess": product_guess,
        "confidence": confidence,
        "bitrix24_modules": bitrix24_modules,
        "common_modules": common_modules,
    }

def get_default_bitrix_modules_db_path() -> Path:
    """
    Return default local SQLite database path with Bitrix module versions.
    """

    project_root = Path(__file__).resolve().parents[3]

    return project_root / "bitrixprobe" / "db" / "db.sqlite"


def parse_installed_module_version_line(line) -> dict:
    """
    Parse installed Bitrix module version line from SSH output.

    Expected examples:
    abtest - 26.0.0 (2026-03-18 20:00:00)
    main - version not detected
    """

    line = line.strip()

    result = {
        "name": "",
        "version": "",
        "version_date": "",
        "raw": line,
    }

    pattern = (
        r"^(?P<name>[a-zA-Z0-9_.-]+)\s+-\s+"
        r"(?P<version>.*?)"
        r"(?:\s+\((?P<version_date>[^)]+)\))?$"
    )

    match = re.search(pattern, line)

    if not match:
        return result

    result["name"] = match.group("name").strip().lower()
    result["version"] = match.group("version").strip()

    version_date = match.group("version_date")

    if version_date:
        result["version_date"] = version_date.strip()

    return result


def parse_registered_modules_json(output) -> list:
    """
    Parse Bitrix runtime registered modules JSON output.
    """

    output = str(output or "").strip()

    if not output:
        return []

    json_start = output.find("[")
    json_end = output.rfind("]")

    if json_start == -1 or json_end == -1 or json_end < json_start:
        return []

    json_text = output[json_start:json_end + 1]

    try:
        items = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    registered_modules = []
    seen_modules = set()

    for item in items:
        if not isinstance(item, dict):
            continue

        module_name = str(item.get("name", "")).strip().lower()

        if not module_name:
            continue

        if module_name in seen_modules:
            continue

        seen_modules.add(module_name)
        registered_modules.append(
            {
                "name": module_name,
                "version": str(item.get("version", "") or "").strip(),
                "installed": bool(item.get("installed", True)),
            }
        )

    return registered_modules


def load_official_bitrix_modules(db_path) -> tuple:
    """
    Load official Bitrix module versions from local SQLite database.
    """

    official_modules = {}
    errors = []

    db_path = Path(db_path)

    if not db_path.exists():
        errors.append(f"Local Bitrix modules database was not found: {db_path}")
        return official_modules, errors

    try:
        connection = sqlite3.connect(db_path)

        try:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT name, description, version, update_date, link
                FROM bitrix_modules
                """
            )

            for row in cursor.fetchall():
                name = row[0]

                official_modules[name] = {
                    "name": row[0],
                    "description": row[1],
                    "version": row[2],
                    "update_date": row[3],
                    "link": row[4],
                }

        finally:
            connection.close()

    except sqlite3.Error as error:
        errors.append(f"SQLite error while reading {db_path}: {error}")

    return official_modules, errors


def parse_version_parts(version) -> list:
    """
    Convert dotted version string into list of integers.
    """

    version = str(version).strip()
    parts = []

    for part in version.split("."):
        if not part.isdigit():
            return []

        parts.append(int(part))

    return parts


def compare_versions(installed_version, official_version):
    """
    Compare installed version with official version.

    Returns:
    - -1 if installed version is older
    - 0 if versions are equal
    - 1 if installed version is newer
    - None if comparison is not possible
    """

    installed_parts = parse_version_parts(installed_version)
    official_parts = parse_version_parts(official_version)

    if not installed_parts:
        return None

    if not official_parts:
        return None

    max_length = max(len(installed_parts), len(official_parts))

    while len(installed_parts) < max_length:
        installed_parts.append(0)

    while len(official_parts) < max_length:
        official_parts.append(0)

    if installed_parts < official_parts:
        return -1

    if installed_parts > official_parts:
        return 1

    return 0


def format_version_with_date(version, version_date) -> str:
    """
    Format module version with optional date.
    """

    if not version:
        version = "not detected"

    if version_date:
        return f"{version} ({version_date})"

    return version


def build_installed_modules_version_comparison(installed_modules_versions, official_modules,
                                               registered_modules=None) -> list:
    """
    Build comparison between installed module versions and official versions.
    """

    compared_modules = []
    registered_modules_by_name = {}

    if registered_modules is None:
        registered_modules = []

    for item in registered_modules:
        module_name = item.get("name", "")
        if module_name:
            registered_modules_by_name[module_name] = item

    for line in installed_modules_versions:
        parsed_module = parse_installed_module_version_line(line)
        module_name = parsed_module["name"]

        if not module_name:
            continue

        registered_module = registered_modules_by_name.get(module_name, {})
        is_installed = module_name in registered_modules_by_name
        installed_version = parsed_module["version"]
        installed_version_date = parsed_module["version_date"]

        if installed_version == "version not detected":
            runtime_version = registered_module.get("version", "")

            if runtime_version:
                installed_version = runtime_version

        official_module = official_modules.get(module_name)

        official_version = ""
        official_update_date = ""
        official_description = ""
        official_link = ""

        if official_module:
            official_version = official_module.get("version", "")
            official_update_date = official_module.get("update_date", "")
            official_description = official_module.get("description", "")
            official_link = official_module.get("link", "")

        version_compare = compare_versions(
            installed_version=installed_version,
            official_version=official_version,
        )

        is_outdated = version_compare == -1

        compared_modules.append(
            {
                "name": module_name,
                "is_installed": is_installed,
                "installation_status": "installed" if is_installed else "not_installed",
                "installed_version": installed_version,
                "installed_version_date": installed_version_date,
                "official_version": official_version,
                "official_update_date": official_update_date,
                "official_description": official_description,
                "official_link": official_link,
                "is_outdated": is_outdated,
                "version_compare": version_compare,
                "raw": parsed_module["raw"],
            }
        )

    return compared_modules


def format_installed_modules_version_comparison(compared_modules) -> str:
    """
    Format installed and official module version comparison.
    """

    lines = []
    lines.append("[Bitrix Installed Modules vs Current Version]")

    if not compared_modules:
        lines.append("No module version data found.")
        return "\n".join(lines)

    for item in compared_modules:
        module_name = item["name"] if "." not in item["name"] else item["name"].split(".")[1] # remove bitrix.eshop etc....
        installed_version = item["installed_version"]
        installed_version_date = item["installed_version_date"]
        official_version = item["official_version"]
        official_update_date = item["official_update_date"]
        status = item.get("installation_status", "unknown")

        module_name_text = bold(blue(module_name))
        installed_version_text = installed_version
        status_text = green("installed") if status == "installed" else "not installed"

        if item["is_outdated"]:
            module_name_text = bold(yellow(module_name))
            installed_version_text = yellow(installed_version)
            official_version = yellow(official_version)

        installed_text = format_version_with_date(
            version=installed_version_text,
            version_date=installed_version_date,
        )

        official_text = "module not found in DB or no info on dev.1c-bitrix.ru/docs/versions.php"

        if official_version:
            official_text = format_version_with_date(
                version=official_version,
                version_date=official_update_date,
            )

        if "module not found" in official_text:
            module_name_text = bold(yellow(module_name))

        lines.append(
            f"-> {module_name_text} - {status_text} - {installed_text} || {official_text}"
        )

    return "\n".join(lines)


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
    """
    Detect Bitrix core version and guess the Bitrix product type.
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
        result["stderr"] = "Webroot is not specified in audit_config."
        return result

    version_file = f"{webroot}/bitrix/modules/main/classes/general/version.php"
    modules_dir = f"{webroot}/bitrix/modules"

    quoted_webroot = shlex.quote(webroot)
    quoted_version_file = shlex.quote(version_file)
    quoted_modules_dir = shlex.quote(modules_dir)

    probes = [
        {
            "key": "core_version",
            "title": "Bitrix Core Version File",
            "command": textwrap.dedent(f"""
version_file={quoted_version_file}

if [ -f "$version_file" ]; then
    grep -E 'SM_VERSION|SM_VERSION_DATE' "$version_file" 2>/dev/null || true
fi
""").strip(),
        },
        {
            "key": "installed_modules",
            "title": "Bitrix Module Directories",
            "command": textwrap.dedent(f"""
modules_dir={quoted_modules_dir}

if [ -d "$modules_dir" ]; then
    for module_dir in "$modules_dir"/*; do
        if [ -d "$module_dir" ]; then
            basename "$module_dir"
        fi
    done | sort -u
fi
""").strip(),
        },
        {
            "key": "registered_modules",
            "title": "Bitrix Runtime Registered Modules",
            "command": textwrap.dedent("""
    webroot=__BITRIXPROBE_WEBROOT__
    prolog_file="$webroot/bitrix/modules/main/include/prolog_before.php"

    if command -v php >/dev/null 2>&1 && [ -f "$prolog_file" ]; then
        BITRIXPROBE_WEBROOT="$webroot" php <<'PHP'
    <?php
    $webroot = getenv('BITRIXPROBE_WEBROOT');

    if (!$webroot)
    {
        fwrite(STDERR, "BITRIXPROBE_WEBROOT is empty\\n");
        exit(1);
    }

    $_SERVER['DOCUMENT_ROOT'] = rtrim($webroot, '/');
    $_SERVER['SERVER_NAME'] = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';

    if (!defined('NO_KEEP_STATISTIC')) define('NO_KEEP_STATISTIC', true);
    if (!defined('NOT_CHECK_PERMISSIONS')) define('NOT_CHECK_PERMISSIONS', true);
    if (!defined('BX_CRONTAB')) define('BX_CRONTAB', true);
    if (!defined('BX_WITH_ON_AFTER_EPILOG')) define('BX_WITH_ON_AFTER_EPILOG', false);

    $prolog = $_SERVER['DOCUMENT_ROOT'] . '/bitrix/modules/main/include/prolog_before.php';

    if (!is_file($prolog))
    {
        fwrite(STDERR, "Bitrix prolog was not found: " . $prolog . "\\n");
        exit(1);
    }

    require_once $prolog;

    $result = array();
    $installedModules = \\Bitrix\\Main\\ModuleManager::getInstalledModules();

    foreach ($installedModules as $moduleId => $row)
    {
        $version = \\Bitrix\\Main\\ModuleManager::getVersion($moduleId);

        $result[] = array(
            'name' => (string)$moduleId,
            'installed' => true,
            'version' => $version ? (string)$version : '',
        );
    }

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    PHP
    else
        if ! command -v php >/dev/null 2>&1; then
            echo "php command was not found" >&2
        else
            echo "Bitrix prolog was not found: $prolog_file" >&2
        fi
        exit 1
    fi
    """).replace("__BITRIXPROBE_WEBROOT__", quoted_webroot).strip(),
        },
        {
            "key": "installed_modules_versions",
            "title": "Bitrix Module Directory Versions",
            "command": textwrap.dedent(f"""
                modules_dir={quoted_modules_dir}
                
                if [ -d "$modules_dir" ]; then
                    for module_dir in "$modules_dir"/*; do
                        if [ -d "$module_dir" ]; then
                            module_name="$(basename "$module_dir")"
                            version_file="$module_dir/install/version.php"
                            main_version_file="$module_dir/classes/general/version.php"
                
                            version="version not detected"
                            version_date=""
                
                            if [ "$module_name" = "main" ]; then
                                if [ -f "$main_version_file" ]; then
                                    extracted_version="$(sed -n -E "s/.*define\\([[:space:]]*[\\"']SM_VERSION[\\"'][[:space:]]*,[[:space:]]*[\\"']([^\\"']+)[\\"'][[:space:]]*\\).*/\\1/p" "$main_version_file" 2>/dev/null | head -n 1)"
                                    extracted_version_date="$(sed -n -E "s/.*define\\([[:space:]]*[\\"']SM_VERSION_DATE[\\"'][[:space:]]*,[[:space:]]*[\\"']([^\\"']+)[\\"'][[:space:]]*\\).*/\\1/p" "$main_version_file" 2>/dev/null | head -n 1)"
                
                                    if [ -n "$extracted_version" ]; then
                                        version="$extracted_version"
                                    fi
                
                                    if [ -n "$extracted_version_date" ]; then
                                        version_date="$extracted_version_date"
                                    fi
                                fi
                            else
                                if [ -f "$version_file" ]; then
                                    extracted_version="$(sed -n -E "s/.*[\\"']VERSION[\\"'][[:space:]]*=>[[:space:]]*[\\"']([^\\"']+)[\\"'].*/\\1/p" "$version_file" 2>/dev/null | head -n 1)"
                                    extracted_version_date="$(sed -n -E "s/.*[\\"']VERSION_DATE[\\"'][[:space:]]*=>[[:space:]]*[\\"']([^\\"']+)[\\"'].*/\\1/p" "$version_file" 2>/dev/null | head -n 1)"
                
                                    if [ -n "$extracted_version" ]; then
                                        version="$extracted_version"
                                    fi
                
                                    if [ -n "$extracted_version_date" ]; then
                                        version_date="$extracted_version_date"
                                    fi
                                fi
                            fi
                
                            if [ -n "$version_date" ]; then
                                echo "$module_name - $version ($version_date)"
                            else
                                echo "$module_name - $version"
                            fi
                        fi
                    done | sort -u
                fi
                """).strip(),
        }
    ]

    probe_results = {}
    stdout_sections = []
    stderr_parts = []

    for probe in probes:
        probe_result = run_bitrix_probe(
            client=client,
            title=probe["title"],
            command=probe["command"],
        )
        #print("[DEBUG]", probe_result)

        probe_results[probe["key"]] = probe_result
        if probe["key"] not in ["installed_modules", "installed_modules_versions", "registered_modules"]:
            stdout_sections.append(format_probe_output(probe_result))
        #print("[DEBUG] probe_results", probe_results)

        if probe_result["stderr"] and probe["key"] != "installed_modules":
            stderr_parts.append(
                f"[{probe_result['title']}]\n{probe_result['stderr']}"
            )

    core_version_output = probe_results["core_version"]["stdout"]
    module_dirs_output = probe_results["installed_modules"]["stdout"]

    core_version = extract_define_value(
        output=core_version_output,
        constant_name="SM_VERSION",
    )

    version_date = extract_define_value(
        output=core_version_output,
        constant_name="SM_VERSION_DATE",
    )

    module_dirs = parse_lines(module_dirs_output)
    registered_modules = parse_registered_modules_json(
        probe_results["registered_modules"]["stdout"]
    )
    registered_module_names = [
        item["name"] for item in registered_modules
    ]

    installed_modules_versions = parse_lines(
        probe_results["installed_modules_versions"]["stdout"]
    )

    classification = classify_bitrix_product(registered_module_names)

    bitrix_modules_db_path = audit_config.get(
        "bitrix_modules_db_path",
        get_default_bitrix_modules_db_path(),
    )

    official_modules, db_errors = load_official_bitrix_modules(
        db_path=bitrix_modules_db_path,
    )

    compared_modules = build_installed_modules_version_comparison(
        installed_modules_versions=installed_modules_versions,
        official_modules=official_modules,
        registered_modules=registered_modules,
    )

    stdout_sections.append(
        format_installed_modules_version_comparison(compared_modules)
    )

    if db_errors:
        stderr_parts.extend(db_errors)

    product_guess = classification["product_guess"]
    confidence = classification["confidence"]
    bitrix24_modules = classification["bitrix24_modules"]
    common_modules = classification["common_modules"]

    detected = bool(core_version or module_dirs or registered_module_names)

    summary = (
        f"Bitrix CMS Guess: {product_guess}\n"
        f"Confidence: {confidence}\n"
        f"Bitrix Core Version: {core_version or 'not detected'}\n"
        f"Bitrix Core Version Date: {version_date or 'not detected'}\n"
        f"Version detect file: {version_file}\n"
        f"Detected Bitrix24 modules: {', '.join(bitrix24_modules) if bitrix24_modules else 'none'}\n"
        f"Detected common modules: {', '.join(common_modules) if common_modules else 'none'}"
    )

    if "bitrix" not in context:
        context["bitrix"] = {}

    context["bitrix"].update(
        {
            "product_guess": product_guess,
            "confidence": confidence,
            "bitrix24_modules": bitrix24_modules,
            "common_modules": common_modules,
            "core_version": core_version,
            "version_date": version_date,
            "version_file": version_file,
            "module_dirs": module_dirs,
            "installed_modules": registered_module_names,
            "registered_modules": registered_modules,
            "installed_modules_versions": installed_modules_versions,
            "installed_modules_versions_compared": compared_modules,
            "bitrix_modules_db_path": str(bitrix_modules_db_path),
            "probes": probe_results,
        }
    )

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = detected
    result["stdout"] = summary + "\n\n" + "\n\n".join(stdout_sections)
    result["stderr"] = "\n\n".join(stderr_parts)


    return result