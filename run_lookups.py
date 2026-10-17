#!/usr/bin/env python3
"""
Runs lookup_indicator against a live NetWitness lab for three indicators
and prints the raw JSON for each. You run this — it is not executed by
the assistant.

Usage:
    export NETWITNESS_API_URL="https://<concentrator-or-broker-ip>:50105"
    export NETWITNESS_USERNAME="<read-only-username>"
    export NETWITNESS_PASSWORD="<read-only-password>"
    # optional, only needed for the incident-scan part of the tool:
    export NW_ADMIN_URL="https://<admin-server-ip>"
    export NW_ADMIN_USERNAME="<username>"
    export NW_ADMIN_PASSWORD="<password>"

    python3 run_lookups.py

No code in netwitness_mcp_server.py is modified by this script.
"""
import asyncio
import importlib.util
import json
import pathlib
import sys

SERVER_PATH = pathlib.Path("/Users/nolanross/projects/netwitness-mcp-server-v2/netwitness_mcp_server.py")

LOOKUPS = [
    ("162.243.103.246", "ip"),
    ("nebula-client.com", "domain"),
    ("8.8.8.8", "ip"),
]


def load_server():
    spec = importlib.util.spec_from_file_location("netwitness_mcp_server", SERVER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["netwitness_mcp_server"] = mod
    spec.loader.exec_module(mod)
    return mod


async def main():
    server = load_server()
    for value, value_type in LOOKUPS:
        print(f"\n=== lookup_indicator({value!r}, {value_type!r}) ===")
        try:
            raw = await server.lookup_indicator(value, value_type)
            print(json.dumps(json.loads(raw), indent=2))
        except Exception as exc:
            print(f"EXCEPTION: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
