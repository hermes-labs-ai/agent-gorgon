from agent_warden.warden import *  # noqa: F401,F403
from agent_warden.warden import entrypoint as _entrypoint

from ._warning import warn_cli as _warn_cli

if __name__ == "__main__":
    _warn_cli()
    raise SystemExit(_entrypoint())
