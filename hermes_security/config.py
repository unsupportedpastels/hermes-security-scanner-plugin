"""Profile-local plugin storage. HERMES_HOME, not a profile label, is the boundary."""
import os
from pathlib import Path


def resolve_data_dir(ctx=None):
    if ctx is not None and getattr(ctx, 'state', None) is not None:
        return Path(ctx.state.data_dir)
    try:
        from hermes_cli.plugins_state import PluginState
    except ImportError:
        return Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes'))).expanduser() / 'plugin-data' / 'hermes-security'
    return Path(PluginState('hermes-security').data_dir)
