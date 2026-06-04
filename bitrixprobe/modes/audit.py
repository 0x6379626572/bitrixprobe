from typing import Dict
from bitrixprobe.modules.ssh_client import connect_ssh
from bitrixprobe.modules.audit_checks import AUDIT_CHECKS
from bitrixprobe.modules.out_report import save_audit_report
from bitrixprobe.console import green, red, yellow, cyan


# Function returns a standard result for check which wasn't launched because its dependencies were not satisfied
def build_skipped_result(check_id, check_name, reason) -> dict:
    return {
        "check_id": check_id,
        "check_name": check_name,
        "exit_code": 0,
        "status": "skipped",
        "detected": False,
        "stdout": reason,
        "stderr": "",
    }
"""Example return:
{
    "check_id": "webserver.apache.enum_configs",
    "check_name": "Apache config enumeration",
    "exit_code": 0,
    "status": "skipped",
    "detected": False,
    "stdout": "Check skipped because dependencies are not satisfied...",
    "stderr": "",
}
"""

# Function checks if we should launch a module
# It returns why module can not be launched, if return is empty then it can be launched
def check_dependencies(check_module, results_by_id) -> list:
    reasons = []

    depends_on = getattr(check_module, "DEPENDS_ON", []) # should have status = "ok"
    requires_detected = getattr(check_module, "REQUIRES_DETECTED", []) # should return detected = True

    for dependency_id in depends_on:
        dependency_result = results_by_id.get(dependency_id)

        if dependency_result is None:
            reasons.append(f"missing dependency: {dependency_id}")
            continue

        if dependency_result["status"] != "ok":
            reasons.append(
                f"dependency is not ok: {dependency_id} "
                f"(status={dependency_result['status']})"
            )

    for dependency_id in requires_detected:
        dependency_result = results_by_id.get(dependency_id)

        if dependency_result is None:
            reasons.append(f"missing detected dependency: {dependency_id}")
            continue

        if dependency_result["status"] != "ok":
            reasons.append(
                f"detected dependency is not ok: {dependency_id} "
                f"(status={dependency_result['status']})"
            )
            continue

        if not dependency_result["detected"]:
            reasons.append(f"dependency was not detected: {dependency_id}")

    return reasons

# Function launches one module
def run_check(client, check_module, audit_config, ssh_config, context, results_by_id) -> dict:
    check_id = check_module.CHECK_ID
    check_name = check_module.CHECK_NAME

    print(cyan("-" * 80))
    print(cyan(f"[*] Running check: {check_name}"))
    print(cyan("-" * 80))

    # Check for module dependencies
    dependency_errors = check_dependencies(
        check_module=check_module,
        results_by_id=results_by_id,
    )

    if dependency_errors:
        reason = "Check skipped because dependencies are not satisfied:\n"
        #reason += "\n".join(f"- {item}" for item in dependency_errors)
        for item in dependency_errors:
            reason += f"- {item}\n"

        skipped_result = build_skipped_result(
            check_id=check_id,
            check_name=check_name,
            reason=reason,
        )

        print(f"[*] Check skipped: {check_name}")
        print(reason)

        return skipped_result

    try:
        result = check_module.run(
            client=client,
            audit_config=audit_config,
            ssh_config=ssh_config,
            context=context,
        )

        result["check_id"] = check_id
        result["check_name"] = check_name

        if result["detected"]:
            print(cyan("[+] Detected: yes\n"))
        else:
            print("[-] Detected: no")

        if result["stdout"]:
            print(result["stdout"].strip())

        if result["stderr"]:
            print(result["stderr"].strip())

        if result["status"] == "skipped":
            print(f"[*] Check skipped: {check_name}\n")
        elif result["exit_code"] == 0:
            print(f"[+] Check done\n")
        else:
            print(f"[!] Check finished with non-zero exit code: {check_name}\n")

        #print("-" * 80)

        return result

    except Exception as error:
        print(f"[-] Check failed: {check_name}: {error}")

        return {
            "check_id": check_id,
            "check_name": check_name,
            "exit_code": 1,
            "status": "error",
            "detected": False,
            "stdout": "",
            "stderr": str(error),
        }

# Main audit function
def run_audit(ssh_config, audit_config) -> int:
    print(
        f"Running audit mode against "
        f"{ssh_config['ssh_user']}@{ssh_config['ssh_host']}:{ssh_config['ssh_port']}"
    )

    client = None
    results = []
    results_by_id = {} # results_by_id - dictionary with the results of finished modules.

    # context - overall dictionary for transferring data between modules.
    # example: context["webservers"]["apache"]["config_paths"] = [...]
    context = {
        "webservers": {},
        "artifacts": {},
    }

    try:
        client = connect_ssh(ssh_config)
        print(green("[+] SSH connection established.\n"))

        # Launch all modules on by one
        for check_module in AUDIT_CHECKS:
            result = run_check(
                client=client,
                check_module=check_module,
                audit_config=audit_config,
                ssh_config=ssh_config,
                context=context,
                results_by_id=results_by_id,
            )

            results.append(result)
            results_by_id[result["check_id"]] = result

        # Make a report
        report_path = save_audit_report(
            results=results,
            ssh_config=ssh_config,
            audit_config=audit_config,
        )
        #print(f"\n[DEBUG] context contents: {context}\n")
        print(f"[+] Audit report saved to: {report_path}\n")

        # Check for failed modules
        failed_checks = []
        for result in results:
            if result["exit_code"] != 0:
                failed_checks.append(result)

        if failed_checks:
            print(yellow(f"[!] Audit finished with {len(failed_checks)} failed checks."))
            return 1

        print(green("[+] Audit finished successfully."))
        return 0

    # Close connection
    finally:
        if client:
            client.close()
            print("[*] SSH connection closed.")
