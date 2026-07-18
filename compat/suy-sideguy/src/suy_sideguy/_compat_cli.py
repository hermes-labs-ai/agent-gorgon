from __future__ import annotations

from agent_warden.forensic_report import main as forensic_main
from agent_warden.warden import entrypoint as warden_entrypoint

from ._warning import warn_cli


def warden() -> int:
    warn_cli()
    return warden_entrypoint()


def forensic_report() -> int:
    warn_cli()
    return forensic_main()
