import sqlite3
from pathlib import Path
from bitrixprobe.console import red_badge, red, yellow, green, blue
from bitrixprobe.modules.audit_checks.detect_bitrix import compare_versions

"""
Search for vulnerable Bitrix modules.
"""

CHECK_ID = "bitrix.vulnerabilities"
CHECK_NAME = "Check Bitrix Installed Module Vulnerabilities"

DEPENDS_ON = ["bitrix.detect"]
REQUIRES_DETECTED = ["bitrix.detect"]


def get_default_vulnerability_db_path() -> Path:
    """
    Return default local SQLite database path with Bitrix vulnerabilities.
    """

    project_root = Path(__file__).resolve().parents[3]

    return project_root / "bitrixprobe" / "db" / "db.sqlite"


def normalize_text(value) -> str:
    """
    Convert nullable database values into stripped strings.
    """

    return str(value or "").strip()


def normalize_module_name(module_name) -> str:
    """
    Normalize Bitrix module names for matching.
    """

    return normalize_text(module_name).lower()


def normalize_cve_id(cve_id) -> str:
    """
    Normalize CVE identifiers for display and cross-table matching.
    """

    cve_id = normalize_text(cve_id).upper()

    if not cve_id:
        return ""

    if cve_id.startswith("CVE-"):
        return cve_id

    return f"CVE-{cve_id}"


def get_cve_match_values(cve_id) -> set:
    """
    Build CVE identifier variants used across local database tables.
    """

    cve_id = normalize_text(cve_id).upper()

    if not cve_id:
        return set()

    values = {cve_id}

    if cve_id.startswith("CVE-"):
        values.add(cve_id[4:])
    else:
        values.add(f"CVE-{cve_id}")

    return values


def parse_cvss_score(score):
    """
    Parse CVSS score from database text.
    """

    score = normalize_text(score)

    if not score:
        return None

    try:
        return float(score.replace(",", "."))
    except ValueError:
        return None


def classify_severity(score) -> dict:
    """
    Convert CVSS score into low, medium or high severity.
    """

    cvss_score = parse_cvss_score(score)

    if cvss_score is None:
        return {"score": "unknown", "cvss": cvss_score}

    if cvss_score >= 9.0:
        return {"score": "critical", "cvss": cvss_score}

    if cvss_score >= 7.0:
        return {"score": "high", "cvss": cvss_score}

    if cvss_score >= 4.0:
        return {"score": "medium", "cvss": cvss_score}

    return {"score": "low", "cvss": cvss_score}


def format_epss(epss_record) -> str:
    """
    Format EPSS score and percentile for human-readable output.
    """

    if not epss_record:
        return "-"

    epss = epss_record.get("epss")
    percentile = epss_record.get("percentile")

    if epss is None or percentile is None:
        return "-"

    return f"{epss * 100:.2f}% ({percentile:.2f})"


def get_installed_modules_from_context(context) -> dict:
    """
    Extract installed Bitrix module versions from bitrix.detect context data.
    """

    bitrix_context = context.get("bitrix", {})
    compared_modules = bitrix_context.get("installed_modules_versions_compared", [])
    installed_modules = {}

    for item in compared_modules:
        module_name = normalize_module_name(item.get("name"))

        if not module_name:
            continue

        if not item.get("is_installed", False):
            continue

        installed_version = normalize_text(item.get("installed_version"))

        if not installed_version or installed_version == "version not detected":
            continue

        installed_modules[module_name] = {
            "name": module_name,
            "version": installed_version,
        }

    if installed_modules:
        return installed_modules

    for item in bitrix_context.get("registered_modules", []): #TODO: ?????
        module_name = normalize_module_name(item.get("name"))

        if not module_name:
            continue

        installed_version = normalize_text(item.get("version"))

        if not installed_version:
            continue

        installed_modules[module_name] = {
            "name": module_name,
            "version": installed_version,
        }

    return installed_modules


def fetch_vulnerability_rows(connection, module_names) -> list:
    """
    Fetch vulnerability rows for installed Bitrix modules.
    """

    if not module_names:
        return []

    #placeholders = ",".join("?" for _ in module_names)
    items = []
    for n in module_names:
        items.append("?")
    placeholders = ",".join(items)

    cursor = connection.cursor()

    cursor.execute(
        f"""
        SELECT
            vuln_id,
            title_en,
            module,
            publication_date,
            detection_date,
            severity_score,
            fix_version,
            bdu_id,
            bdu_link,
            cve_id,
            cve_link,
            link
        FROM bitrix_vulnerabilities
        WHERE lower(trim(module)) IN ({placeholders})
        """,
        list(module_names),
    )

    return cursor.fetchall()


def fetch_pt_trends(connection) -> dict:
    """
    Load PT trends identifiers for CVE and BDU matching.
    """

    cursor = connection.cursor()
    cursor.execute("SELECT cve, bdu FROM pt_trends")

    cve_values = set()
    bdu_values = set()

    for cve_id, bdu_id in cursor.fetchall():
        for value in get_cve_match_values(cve_id):
            cve_values.add(value)

        bdu_id = normalize_text(bdu_id)

        if bdu_id:
            bdu_values.add(bdu_id)

    return {
        "cve": cve_values,
        "bdu": bdu_values,
    }


def fetch_epss_records(connection, cve_values) -> dict:
    """
    Load EPSS records for CVE identifiers referenced by vulnerabilities.
    """

    if not cve_values:
        return {}

    #placeholders = ",".join("?" for _ in cve_values)
    items = []
    for n in cve_values:
        items.append("?")
    placeholders = ",".join(items)

    cursor = connection.cursor()

    cursor.execute(
        f"""
        SELECT cve, epss, percentile
        FROM epss_records
        WHERE upper(cve) IN ({placeholders})
        """,
        [value.upper() for value in cve_values],
    )

    epss_records = {}

    for cve_id, epss, percentile in cursor.fetchall():
        for value in get_cve_match_values(cve_id):
            epss_records[value] = {
                "epss": epss,
                "percentile": percentile,
            }

    return epss_records


def build_vulnerability_items(installed_modules, vulnerability_rows,
                              pt_trends, epss_records) -> list:
    """
    Compare installed module versions with vulnerability fix versions.
    """

    vulnerabilities = []

    for row in vulnerability_rows:
        (
            vuln_id,
            title_en,
            module_name,
            publication_date,
            detection_date,
            severity_score,
            fix_version,
            bdu_id,
            bdu_link,
            cve_id,
            cve_link,
            link,
        ) = row

        module_name = normalize_module_name(module_name)
        fix_version = normalize_text(fix_version)

        if not module_name or not fix_version:
            continue

        installed_module = installed_modules.get(module_name)

        if not installed_module:
            continue

        installed_version = installed_module["version"]
        version_compare = compare_versions(installed_version, fix_version) # Function from detect_bitrix.py

        if version_compare != -1:
            continue

        cve_display = normalize_cve_id(cve_id)
        cve_match_values = get_cve_match_values(cve_id)
        bdu_id = normalize_text(bdu_id)

        is_pt_trending = False

        for value in cve_match_values:
            if value in pt_trends["cve"]:
                is_pt_trending = True
                break

        if bdu_id and bdu_id in pt_trends["bdu"]:
            is_pt_trending = True

        epss_record = None

        for value in cve_match_values:
            if value in epss_records:
                epss_record = epss_records[value]
                break

        severity_info = classify_severity(severity_score)
        severity = severity_info["score"]
        cvss = severity_info["cvss"]
        cvss_text = f"{cvss:g}" if cvss is not None else "-"

        if severity in ["critical", "high"]:
            severity = red(severity)
            cvss_text = red(cvss_text)
        elif severity == "medium":
            severity = yellow(severity)
            cvss_text = yellow(cvss_text)
        elif severity == "low":
            severity = blue(severity)
            cvss_text = blue(cvss_text)

        vulnerabilities.append(
            {
                "vuln_id": normalize_text(vuln_id),
                "module": module_name,
                "installed_version": installed_version,
                "title": normalize_text(title_en) or normalize_text(vuln_id),
                "severity": severity,
                "cvss": cvss_text,
                "fix_version": fix_version,
                "bdu": bdu_id or "-",
                "bdu_link": normalize_text(bdu_link),
                "cve": cve_display or "-",
                "cve_link": normalize_text(cve_link),
                "link": normalize_text(link),
                "discovered": normalize_text(detection_date) or "-",
                "published": normalize_text(publication_date) or "-",
                "pt_trending": is_pt_trending,
                "epss": format_epss(epss_record),
            }
        )

    vulnerabilities.sort(
        key=lambda item: (
            item["module"],
            item["fix_version"],
            item["vuln_id"],
        )
    )

    return vulnerabilities


def format_links(item) -> list:
    """
    Build vulnerability links list without duplicates.
    """

    links = []

    for key in ["link", "bdu_link", "cve_link"]:
        link = item.get(key, "")

        if link and link not in links:
            links.append(link.replace("http", "h_ttp").replace("www.", ""))

    return links


def format_vulnerabilities(vulnerabilities) -> str:
    """
    Format vulnerable module versions for terminal and report output.
    """

    lines = []
    lines.append("\n")
    lines.append("Vulnerable versions:")
    lines.append("------------------------------")

    if not vulnerabilities:
        lines.append("No vulnerable installed Bitrix module versions were detected.")
        return "\n".join(lines)

    for item in vulnerabilities:
        pt_trending = ""

        if item["pt_trending"]:
            pt_trending = f" {red_badge('PT-TRENDING')}"
        lines.append(f"MODULE:{blue(item['module'].upper())} VERSION:{blue(item['installed_version'])}"f"  {pt_trending}")
        lines.append(f"Vulnerability: {blue(item['title'])}")
        lines.append(f"Severity:{item['severity']} CVSS:{item['cvss']}")
        lines.append(f"BDU:{blue(item['bdu'])} CVE:{blue(item['cve'])} EPSS:{blue(item['epss'])}")
        lines.append(f"Discovered:{blue(item['discovered'])} Published:{blue(item['published'])}")
        lines.append(f"FIXED VERSION:{blue(item['fix_version'])}")
        lines.append("Links:")

        links = format_links(item)

        if links:
            lines.extend(links)
        else:
            lines.append("-")

        lines.append("")

    return "\n".join(lines).rstrip()


def run(client, audit_config, ssh_config, context) -> dict:
    """
    Check installed Bitrix module versions against local vulnerability database.
    """

    result = {
        "exit_code": 1,
        "status": "error",
        "detected": False,
        "stdout": "",
        "stderr": "",
    }

    installed_modules = get_installed_modules_from_context(context)

    if not installed_modules:
        result["exit_code"] = 0
        result["status"] = "ok"
        result["stdout"] = "Bitrix installed module version data was not found in context."
        return result

    db_path = Path(audit_config.get("bitrix_vulnerabilities_db_path", get_default_vulnerability_db_path(),))

    if not db_path.exists():
        result["stderr"] = f"Local vulnerabilities database was not found: {db_path}"
        return result

    try:
        connection = sqlite3.connect(db_path)

        try:
            vulnerability_rows = fetch_vulnerability_rows(
                connection=connection,
                module_names=installed_modules.keys(),
            )
            pt_trends = fetch_pt_trends(connection)

            cve_values = set()

            for row in vulnerability_rows:
                cve_values.update(get_cve_match_values(row[9]))

            epss_records = fetch_epss_records(
                connection=connection,
                cve_values=cve_values,
            )

            vulnerabilities = build_vulnerability_items(
                installed_modules=installed_modules,
                vulnerability_rows=vulnerability_rows,
                pt_trends=pt_trends,
                epss_records=epss_records,
            )

        finally:
            connection.close()

    except sqlite3.Error as error:
        result["stderr"] = f"SQLite error while reading {db_path}: {error}"
        return result

    if "bitrix" not in context:
        context["bitrix"] = {}

    context["bitrix"]["vulnerabilities"] = {
        "detected": bool(vulnerabilities),
        "database_path": str(db_path),
        "installed_modules_checked": sorted(installed_modules.keys()),
        "items": vulnerabilities,
    }

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = bool(vulnerabilities)
    result["stdout"] = format_vulnerabilities(vulnerabilities)

    return result
