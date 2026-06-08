from bitrixprobe.modules.audit_checks import enum_remote_identity
from bitrixprobe.modules.audit_checks import enum_php
from bitrixprobe.modules.audit_checks import enum_webroot_files
from bitrixprobe.modules.audit_checks import detect_apache
from bitrixprobe.modules.audit_checks import detect_nginx
from bitrixprobe.modules.audit_checks import enum_apache_config
from bitrixprobe.modules.audit_checks import enum_nginx_config
from bitrixprobe.modules.audit_checks import enum_docker
from bitrixprobe.modules.audit_checks import detect_bitrix
from bitrixprobe.modules.audit_checks import check_bitrix_vulnerabilities
from bitrixprobe.modules.audit_checks import check_bitrix_restore
from bitrixprobe.modules.audit_checks import check_bitrix_setup

"""
---------------------------
Compile list of modules.-
---------------------------
"""

# Each audit check must return a standard result dictionary:
# exit_code, status, detected, stdout, stderr.
AUDIT_CHECKS = [
    #OS enumeration
    enum_remote_identity,
    enum_php,
    enum_docker,

    # Webserver enumeration
    detect_apache,
    enum_apache_config,
    detect_nginx,
    enum_nginx_config,
    enum_webroot_files,

    # Bitrix enumeration
    detect_bitrix,

    # Vulnerability detection
    check_bitrix_restore,
    check_bitrix_setup,
    check_bitrix_vulnerabilities

]