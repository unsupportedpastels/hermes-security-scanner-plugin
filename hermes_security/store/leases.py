"""Atomic finalization leases; callers hold a write transaction and check sealing."""

import math
import time
from hermes_security.errors import ValidationError


def lease(connection, scan_id, owner, ttl_s):
    if (
        not isinstance(owner, str)
        or not owner
        or not isinstance(ttl_s, (int, float))
        or not math.isfinite(ttl_s)
        or ttl_s <= 0
    ):
        raise ValidationError("lease requires an owner and a positive finite TTL")
    now = time.time()
    result = connection.execute(
        """INSERT INTO leases(scan_id,owner,expires_at) VALUES(?,?,?)
        ON CONFLICT(scan_id) DO UPDATE SET owner=excluded.owner, expires_at=excluded.expires_at
        WHERE leases.expires_at<=? OR leases.owner=excluded.owner""",
        (scan_id, owner, now + ttl_s, now),
    )
    return result.rowcount == 1


def release(connection, scan_id, owner):
    connection.execute(
        "DELETE FROM leases WHERE scan_id=? AND owner=?", (scan_id, owner)
    )
