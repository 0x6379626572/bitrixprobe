import sqlite3
from pathlib import Path

"""
Shared SQLite helpers for BitrixProbe modules.
"""


def get_project_root() -> Path:
    """
    Return the BitrixProbe project root directory.
    """

    return Path(__file__).resolve().parents[2]


def get_default_db_path() -> Path:
    """
    Return default local SQLite database path.
    """

    return get_project_root() / "bitrixprobe" / "db" / "db.sqlite"


def get_default_vulnerability_metadata(cve_id="", bdu_id="") -> dict:
    """
    Return an empty vulnerability metadata structure.
    """

    return {
        "vuln_id": "",
        "title": "",
        "cve": normalize_cve_id(cve_id),
        "bdu": normalize_bdu_id(bdu_id),
        "vendor_link": "",
        "bdu_link": "",
        "cve_link": "",
        "severity_score": "",
        "module": "",
        "fix_version": "",
        "source": "",
        "found": False,
    }


def normalize_text(value) -> str:
    """
    Convert nullable database values into stripped strings.
    """

    return str(value or "").strip()


def normalize_cve_id(cve_id) -> str:
    """
    Normalize a CVE identifier for display.
    """

    cve_id = normalize_text(cve_id).upper()

    if not cve_id:
        return ""

    if cve_id.startswith("CVE-"):
        return cve_id

    return f"CVE-{cve_id}"


def normalize_bdu_id(bdu_id) -> str:
    """
    Normalize a BDU identifier for display.
    """

    bdu_id = normalize_text(bdu_id).upper()

    if not bdu_id:
        return ""

    for prefix in ["BDU:", "BDU-", "BDU "]:
        if bdu_id.startswith(prefix):
            return bdu_id[len(prefix):]

    return bdu_id


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


def get_bdu_match_values(bdu_id) -> set:
    """
    Build BDU identifier variants used across local database tables.
    """

    bdu_id = normalize_text(bdu_id).upper()

    if not bdu_id:
        return set()

    clean_bdu = normalize_bdu_id(bdu_id)
    values = {bdu_id, clean_bdu}
    values.add(f"BDU:{clean_bdu}")
    values.add(f"BDU-{clean_bdu}")
    values.add(f"BDU {clean_bdu}")

    return values


def fetch_bitrix_vulnerability_metadata(cve_id="", bdu_id="", db_path=None) -> dict:
    """
    Fetch one Bitrix vulnerability row by CVE or BDU identifier.
    """

    metadata = get_default_vulnerability_metadata(
        cve_id=cve_id,
        bdu_id=bdu_id,
    )

    db_path = Path(db_path or get_default_db_path())

    if not db_path.exists():
        return metadata

    cve_values = sorted(get_cve_match_values(cve_id))
    bdu_values = sorted(get_bdu_match_values(bdu_id))

    if not cve_values and not bdu_values:
        return metadata

    where_parts = []
    params = []

    if cve_values:
        cve_placeholders = ",".join("?" for _ in cve_values)
        where_parts.append(f"upper(trim(cve_id)) IN ({cve_placeholders})")
        params.extend(value.upper() for value in cve_values)

    if bdu_values:
        bdu_placeholders = ",".join("?" for _ in bdu_values)
        where_parts.append(f"upper(trim(bdu_id)) IN ({bdu_placeholders})")
        params.extend(value.upper() for value in bdu_values)

    where_clause = " OR ".join(where_parts)

    try:
        with sqlite3.connect(db_path) as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            cursor.execute(
                f"""
                SELECT
                    vuln_id,
                    title_en,
                    title,
                    module,
                    severity_score,
                    fix_version,
                    bdu_id,
                    bdu_link,
                    cve_id,
                    cve_link,
                    link,
                    source
                FROM bitrix_vulnerabilities
                WHERE {where_clause}
                LIMIT 1
                """,
                params,
            )

            row = cursor.fetchone()
    except sqlite3.Error as error:
        metadata["db_error"] = str(error)
        return metadata

    if not row:
        return metadata

    title = normalize_text(row["title_en"]) or normalize_text(row["title"])
    cve = normalize_cve_id(row["cve_id"]) or normalize_cve_id(cve_id)
    bdu = normalize_bdu_id(row["bdu_id"]) or normalize_bdu_id(bdu_id)

    metadata.update(
        {
            "vuln_id": normalize_text(row["vuln_id"]),
            "title": title,
            "cve": cve,
            "bdu": bdu,
            "vendor_link": normalize_text(row["link"]),
            "bdu_link": normalize_text(row["bdu_link"]),
            "cve_link": normalize_text(row["cve_link"]),
            "severity_score": normalize_text(row["severity_score"]),
            "module": normalize_text(row["module"]),
            "fix_version": normalize_text(row["fix_version"]),
            "source": normalize_text(row["source"]),
            "found": True,
        }
    )

    return metadata
