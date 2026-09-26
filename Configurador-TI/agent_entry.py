"""Dedicated PyInstaller entry; independent from the Technician GUI."""
from agent.__main__ import main
from licensing.contracts import Denied
if __name__=='__main__':
    try: main()
    except (Denied,OSError,ValueError,KeyError) as e: raise SystemExit(getattr(e,'code','AGENT_STATE_UNAVAILABLE')) from None
