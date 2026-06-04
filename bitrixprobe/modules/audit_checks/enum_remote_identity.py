from bitrixprobe.modules.ssh_client import run_remote_shell

"""
Enumerate remote identity.
"""

CHECK_ID = "system.remote_identity.enum"
CHECK_NAME = "Remote identity enumeration"

DEPENDS_ON = []
REQUIRES_DETECTED = []


def run(client, audit_config, ssh_config, context) -> dict:
    # Initialize a standard result dictionary for this audit check.
    result = {
        "exit_code": 1,
        "status": "error",
        "detected": False,
        "stdout": "",
        "stderr": "",
    }

    user_result = run_remote_shell(client, "whoami")
    id_result = run_remote_shell(client, "id")
    host_result = run_remote_shell(client, "hostname")
    uname_result = run_remote_shell(client, "uname -a")

    username = user_result["stdout"].strip()
    user_identity = id_result["stdout"].strip()
    hostname = host_result["stdout"].strip()
    os_info = uname_result["stdout"].strip()


    stderr_parts = []
    if user_result["stderr"]:
        stderr_parts.append(user_result["stderr"].strip())
    if host_result["stderr"]:
        stderr_parts.append(host_result["stderr"].strip())
    if id_result["stderr"]:
        stderr_parts.append(id_result["stderr"].strip())
    if uname_result["stderr"]:
        stderr_parts.append(uname_result["stderr"].strip())

    command_failed = (
        user_result["exit_code"] != 0
        or host_result["exit_code"] != 0
        or id_result["exit_code"] != 0
        or uname_result["exit_code"] != 0
    )

    result["stdout"] = (
        f"Username: {username}\n"
        f"Identity: {user_identity}"
        f"Hostname: {hostname}\n"
        f"OS: {os_info}\n"
    )

    result["stderr"] = "\n".join(stderr_parts)

    if command_failed:
        result["exit_code"] = 1
        result["status"] = "error"
        result["detected"] = False

        return result

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = bool(username and hostname and user_identity and os_info)

    if not command_failed:
        if "system" not in context:
            context["system"] = {}

        context["system"]["remote_identity"] = {
            "username": username,
            "identity": user_identity,
            "hostname": hostname,
            "os": os_info
        }

    return result