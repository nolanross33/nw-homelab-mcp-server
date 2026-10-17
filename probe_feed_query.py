#!/usr/bin/env python3
"""
probe_feed_query.py — sends five read-only GET queries to the Broker's
/sdk?msg=query endpoint, to compare feed-check query-syntax variants for
indicator 162.243.103.246 (paren-OR vs comma-list device.type, 7d vs 168h
time window, full select list vs sessionid,time only). Prints the exact
query string, HTTP status, and first 300 chars of the response body for
each variant. Read-only GETs only; sends nothing else. You run this — it
is not executed by the assistant.

Usage:
    export NETWITNESS_API_URL="https://<broker-ip>:50105"
    export NETWITNESS_USERNAME="<read-only-username>"
    export NETWITNESS_PASSWORD="<read-only-password>"

    python3 probe_feed_query.py

No code in netwitness_mcp_server.py is modified or imported by this script.
"""
import os
import sys
from urllib.parse import quote_plus

import httpx

INDICATOR = "162.243.103.246"
SIZE = 1000
TIMEOUT = 30.0
BODY_PREVIEW_LEN = 300

SELECT_FULL = "device.type,threat.desc,threat.category,result,event.type,event.desc,ip.dstport,time"

VARIANTS = [
    (
        "A",
        "current feed query (paren-OR), window swapped to 168h instead of 7d",
        f"select {SELECT_FULL} where "
        f"(device.type='abuse.ch_feodo' || device.type='abuse.ch_urlhaus') "
        f"&& ip.dst={INDICATOR} && time=rtp(now,168h)-u",
    ),
    (
        "B",
        "comma-list device.type form, 168h window, same select list",
        f"select {SELECT_FULL} where "
        f"device.type='abuse.ch_feodo','abuse.ch_urlhaus' "
        f"&& ip.dst={INDICATOR} && time=rtp(now,168h)-u",
    ),
    (
        "C",
        "comma-list device.type form, 7d window, same select list",
        f"select {SELECT_FULL} where "
        f"device.type='abuse.ch_feodo','abuse.ch_urlhaus' "
        f"&& ip.dst={INDICATOR} && time=rtp(now,7d)-u",
    ),
    (
        "D",
        "single feed (feodo only), minimal select (sessionid,time), 168h window",
        f"select sessionid,time where "
        f"device.type='abuse.ch_feodo' "
        f"&& ip.dst={INDICATOR} && time=rtp(now,168h)-u",
    ),
    (
        "E",
        "current parenthesised || form, 168h window",
        f"select {SELECT_FULL} where "
        f"(device.type='abuse.ch_feodo' || device.type='abuse.ch_urlhaus') "
        f"&& ip.dst={INDICATOR} && time=rtp(now,168h)-u",
    ),
]


def main() -> int:
    api_url = os.environ.get("NETWITNESS_API_URL", "").strip()
    username = os.environ.get("NETWITNESS_USERNAME", "").strip()
    password = os.environ.get("NETWITNESS_PASSWORD", "").strip()

    if not api_url or not username or not password:
        print(
            "NETWITNESS_API_URL, NETWITNESS_USERNAME, and NETWITNESS_PASSWORD "
            "must all be set.",
            file=sys.stderr,
        )
        return 1

    with httpx.Client(auth=(username, password), verify=False, timeout=TIMEOUT) as client:
        for letter, label, query_str in VARIANTS:
            url = (
                f"{api_url}/sdk?msg=query"
                f"&force-content-type=application/json&size={SIZE}"
                f"&query={quote_plus(query_str)}"
            )
            print(f"\n=== Variant {letter}: {label} ===")
            print(f"query: {query_str}")
            try:
                resp = client.get(url)
                print(f"HTTP status: {resp.status_code}")
                print(f"body (first {BODY_PREVIEW_LEN} chars): {resp.text[:BODY_PREVIEW_LEN]}")
            except Exception as exc:
                print(f"EXCEPTION: {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
