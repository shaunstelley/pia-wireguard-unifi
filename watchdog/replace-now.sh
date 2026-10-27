#!/usr/bin/env bash
# Replace the router's PIA config right now.
exec "$(dirname "$0")/sandboxed.sh" --replace-now
