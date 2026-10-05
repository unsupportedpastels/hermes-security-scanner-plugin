"""Lazy Hermes plugin entry point; importing this file performs no registration."""


def register(ctx):
    """Register the service only when the Hermes host requests it."""
    import hermes_security.plugin

    return hermes_security.plugin.register(ctx)
