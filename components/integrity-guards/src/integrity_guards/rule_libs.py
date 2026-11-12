"""Small rule libraries for audit scripts. Pure functions.

R-BILLING-AUDIT  states an operator declared normal must not be reported as anomalies;
                 a subscriber binding is removed only on live forwarding-table evidence.
R-FRESH-MONITOR  a monitor sample older than two poll intervals must not be reported as active.

Values that describe one network (tariff ids, parked address prefixes, uplink ports)
are parameters; callers take them from their own configuration.
"""
from __future__ import annotations

import time
from collections.abc import Iterable


def billing_card_is_anomaly(card: dict, *, prepaid_tariffs: Iterable[int] = (),
                            parked_ip_prefixes: Iterable[str] = ()) -> bool:
    """False for states declared normal: a prepaid tariff with money, or a parked address."""
    if int(card.get("paket", -1)) in set(prepaid_tariffs) and float(card.get("balance", 0)) > 0:
        return False
    ip = str(card.get("ip", ""))
    if any(prefix and ip.startswith(prefix) for prefix in parked_ip_prefixes):
        return False
    return bool(card.get("flagged", True))


def gpon_unbind_allowed(binding: dict, fdb_other_client_macs: int | None, *,
                        protected_ports: Iterable[tuple[str, str]] = ()) -> tuple[bool, str]:
    """Unbind only with live FDB proof of another client on that ONU; never for inactive-only evidence.

    ``protected_ports`` lists (switch address, port) pairs that are uplinks and never unbound.
    """
    if fdb_other_client_macs is None:
        return False, "no live FDB read: age/off state alone is not evidence"
    if fdb_other_client_macs <= 0:
        return False, "FDB shows no other client on this ONU"
    key = (str(binding.get("switch_ip")), str(binding.get("port")))
    if key in {(str(a), str(b)) for a, b in protected_ports}:
        return False, f"{key[0]}:{key[1]} is a protected uplink port; leave it"
    return True, "FDB shows another client's MAC; removal may be proposed (operator GO still needed)"


def monitor_freshness(sample_ts: float, poll_interval_s: float, now: float | None = None) -> dict:
    """Stale = older than 2 poll intervals. Callers must not report a stale 'active' state."""
    now = time.time() if now is None else now
    age = now - float(sample_ts)
    stale = age > 2 * float(poll_interval_s)
    return {"age_seconds": round(age, 1), "stale": stale,
            "banner": f"STALE_MONITOR_DATA (age={age:.0f}s): DO NOT REPORT AS ACTIVE" if stale else ""}
