from agent_warden.forensic_report import *  # noqa: F401,F403
from agent_warden.forensic_report import main as _main

from ._warning import warn_cli as _warn_cli

if __name__ == "__main__":
    _warn_cli()
    raise SystemExit(_main())
