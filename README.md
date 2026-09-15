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

## Architecture

- **`netwitness_mcp_server.py`** — the server itself, built on the official
  [`mcp`](https://pypi.org/project/mcp/) Python SDK (`FastMCP`). Talks to a
  NetWitness Concentrator/Broker for session/meta/alert data and to the
  NetWitness Admin Server REST API for incident management. All credentials
  and endpoints come from environment variables — nothing is hardcoded.
- **`Dockerfile`** — packages the server as a container image, run as a
  non-root user.
- **`config/`** — reference configs for wiring this into
  [Docker's MCP Gateway/Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/)
  and Claude Desktop, both local (same host) and remote (server on a
  different host than the MCP client).

## Setup

Requires a NetWitness environment (Concentrator/Broker + Admin Server) and
Docker Desktop with the MCP Toolkit.

```bash
docker build -t netwitness-mcp-server .

docker mcp secret set NETWITNESS_API_URL="https://<concentrator-or-broker-ip>:50105"
docker mcp secret set NETWITNESS_USERNAME="<username>"
docker mcp secret set NETWITNESS_PASSWORD="<password>"
docker mcp secret set NW_ADMIN_URL="https://<admin-server-ip>"
docker mcp secret set NW_ADMIN_USERNAME="<username>"
docker mcp secret set NW_ADMIN_PASSWORD="<password>"
```

Then register the server with Docker's MCP catalog/registry using the files
in `config/docker-mcp-catalog.yaml` and `config/docker-mcp-registry.yaml`
(copy or merge into `~/.docker/mcp/catalogs/custom.yaml` and
`~/.docker/mcp/registry.yaml`), and point your MCP client at it — see
`config/claude_desktop_config.local.json` for same-host setup or
`config/claude_desktop_config.remote.json` plus an
[MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/) container
for cross-host setup.

## Notes

- This talks to NetWitness's own REST APIs the way any external integration
  would — it doesn't embed or redistribute any NetWitness product code.
- Not affiliated with or endorsed by RSA/NetWitness. Built independently
  against a personal home lab instance.
