from bitrixprobe.modes.audit import run_audit
from bitrixprobe.modes.pentest import run_pentest
from bitrixprobe.config import build_audit_config, build_pentest_config, build_ssh_config, parse_args
from bitrixprobe.console import error_message, hint_message

"""
==================
Main entry point.=
==================
"""

def main(argv=None):
    try:
        args = parse_args(argv)

        """
        Run audit scan
        """
        if args.mode == "audit":
            ssh_config = build_ssh_config(args)
            audit_config = build_audit_config(args)

            return run_audit(ssh_config, audit_config)

        """
        Run pentest scan
        """
        if args.mode == "pentest":
            pentest_config = build_pentest_config(args)
            return run_pentest(pentest_config)

        print(error_message(f"Unknown mode: {args.mode}"))
        return 2

    except ValueError as error:
        print(error_message(str(error)))
        print(hint_message("Use --webroot /path/to/site or set BP_WEBROOT in .env."))
        return 2



if __name__ == "__main__":
    raise SystemExit(main())