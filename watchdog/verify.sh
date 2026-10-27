#!/usr/bin/env bash
# Check the router and PIA logins and the VPN client's status, changing nothing.
exec "$(dirname "$0")/sandboxed.sh" --verify
