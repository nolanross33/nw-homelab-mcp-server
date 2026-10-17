#!/usr/bin/env bash
# Prompts interactively for NetWitness lab credentials, runs
# probe_feed_query.py against them, then unsets the credentials. Nothing
# is hardcoded here — you type the URL, username, and password each time
# this runs.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

read -p "NetWitness API URL: " NETWITNESS_API_URL
read -p "NetWitness username: " NETWITNESS_USERNAME
read -s -p "NetWitness password: " NETWITNESS_PASSWORD
echo

export NETWITNESS_API_URL
export NETWITNESS_USERNAME
export NETWITNESS_PASSWORD

python3 probe_feed_query.py
status=$?

unset NETWITNESS_API_URL
unset NETWITNESS_USERNAME
unset NETWITNESS_PASSWORD

exit "$status"
