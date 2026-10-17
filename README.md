# netwitness-mcp-server

A Model Context Protocol (MCP) server that lets an LLM agent (Claude, or any
other MCP-compatible client) query a NetWitness environment directly —
sessions, meta values, alerts, and incidents — through natural-language
requests instead of hand-written queries against the NetWitness UI or REST
API.

Built against the NetWitness home lab described in my other repos, mainly to
answer a practical question: *can an agent actually reason usefully about
detection/response data if it's given the right tools, instead of just a raw
API wrapper?* This is the tool layer that lets it try.

See `INSTALL.txt` for setup.

## What it exposes

Nine tools, each returning a consistent JSON envelope (`status`, `tool`,
`query`, `data`, `metadata`, `error`) so a calling agent can parse results
predictably instead of guessing at response shape:

| Tool | Purpose |
|---|---|
| `query_sessions` | Query session/packet metadata from a Concentrator or Broker |
| `query_metakey_values` | List distinct values for a given meta key |
| `query_alerts` | Query alerts by criteria |
| `get_netwitness_meta_keys` | List available meta keys and their descriptions |
| `get_netwitness_query_syntax` | Return NetWitness query syntax reference |
| `query_incidents` | Query incidents from the Admin Server / Respond module |
| `query_incident_alerts` | Get alerts tied to a specific incident |
| `update_incident_status` | Change an incident's status |
| `add_incident_journal_entry` | Add a journal entry to an incident |
| `lookup_indicator` | Check if an IP, domain, or URL is in threat feeds and has appeared in sessions/incidents |

## lookup_indicator — indicator pivot tool (v2)

`lookup_indicator(value, value_type)` answers one question in a single
call: is this IP, domain, or URL in my threat feeds, has it shown up in
traffic, and is it linked to any open incidents? `value_type` is one of
`ip`, `domain`, or `url`.

It checks:

- **Threat feeds** — cross-references the URLhaus and Feodo Tracker feeds
  (see [`homelab-iac/threat-intel`](https://github.com/nolanross33/homelab-iac/tree/main/threat-intel))
  over NetWitness's retention window
- **Session activity** — whether the indicator has appeared in network
  sessions recently, with first/last-seen timestamps
- **Linked incidents** — any open Respond incidents that reference it

Input is validated and sanitized before it's used in a query or returned in
a response.

## Notes

- This talks to NetWitness's own REST APIs the way any external integration
  would — it doesn't embed or redistribute any NetWitness product code.
- Not affiliated with or endorsed by RSA/NetWitness. Built independently
  against a personal home lab instance.
