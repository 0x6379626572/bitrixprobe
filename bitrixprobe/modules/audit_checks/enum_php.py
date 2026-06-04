from bitrixprobe.modules.ssh_client import run_remote_shell

"""
Enumerate PHP on remote server.
"""

CHECK_ID = "system.php.enum"
CHECK_NAME = "Remote php enumeration"

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

    # Run command
    php_result = run_remote_shell(client, "php -v")

    # Normalise stdout
    php_stdout = php_result["stdout"].strip()
    # Error result
    php_stderr = php_result["stderr"].strip()

    if php_result["exit_code"] == 0 and php_stdout:
        result["exit_code"] = 0
        result["status"] = "ok"
        result["detected"] = True
        result["stdout"] = f"PHP CLI detected:\n{php_stdout}"
        result["stderr"] = php_stderr

        if "system" not in context:
            context["system"] = {}

        context["system"]["php"] = {
            "detected": True,
            "cli_version_output": php_stdout,
        }

        return result

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = False
    result["stdout"] = "PHP CLI was not detected via `php -v`."
    result["stderr"] = php_stderr

    if "system" not in context:
        context["system"] = {}

    context["system"]["php"] = {
        "detected": False,
        "cli_version_output": "",
    }

    return result