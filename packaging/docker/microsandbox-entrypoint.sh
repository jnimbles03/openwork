#!/usr/bin/env sh
set -eu

OPENWORK_WORKSPACE="${OPENWORK_WORKSPACE:-/workspace}"
OPENWORK_DATA_DIR="${OPENWORK_DATA_DIR:-/data/openwork-orchestrator}"
OPENWORK_SIDECAR_DIR="${OPENWORK_SIDECAR_DIR:-/data/sidecars}"
OPENWORK_PORT="${OPENWORK_PORT:-8787}"
OPENWORK_OPENCODE_PORT="${OPENWORK_OPENCODE_PORT:-4096}"
OPENWORK_APPROVAL_MODE="${OPENWORK_APPROVAL_MODE:-manual}"
OPENWORK_CONNECT_HOST="${OPENWORK_CONNECT_HOST:-127.0.0.1}"
OPENWORK_CORS_ORIGINS="${OPENWORK_CORS_ORIGINS:-http://$OPENWORK_CONNECT_HOST:$OPENWORK_PORT}"
HOME="${HOME:-/root}"
USER="${USER:-root}"
SHELL="${SHELL:-/bin/sh}"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

if [ "$HOME" = "/" ]; then
  HOME=/root
  XDG_CONFIG_HOME="$HOME/.config"
  XDG_CACHE_HOME="$HOME/.cache"
  XDG_DATA_HOME="$HOME/.local/share"
  XDG_STATE_HOME="$HOME/.local/state"
fi

export HOME USER SHELL XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME XDG_STATE_HOME

random_token() {
  token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  if [ "${#token}" -ne 64 ]; then
    printf '%s\n' "failed to generate a random OpenWork token from /dev/urandom" >&2
    exit 1
  fi
  printf '%s' "$token"
}

OPENWORK_TOKEN_SOURCE="OPENWORK_TOKEN"
if [ -z "${OPENWORK_TOKEN:-}" ]; then
  OPENWORK_TOKEN="$(random_token)"
  OPENWORK_TOKEN_SOURCE="generated"
fi
OPENWORK_HOST_TOKEN_SOURCE="OPENWORK_HOST_TOKEN"
if [ -z "${OPENWORK_HOST_TOKEN:-}" ]; then
  OPENWORK_HOST_TOKEN="$(random_token)"
  OPENWORK_HOST_TOKEN_SOURCE="generated"
fi
if [ "$OPENWORK_TOKEN" = "$OPENWORK_HOST_TOKEN" ]; then
  printf '%s\n' "OPENWORK_TOKEN and OPENWORK_HOST_TOKEN must be different" >&2
  exit 1
fi

mkdir -p "$OPENWORK_WORKSPACE" "$OPENWORK_DATA_DIR" "$OPENWORK_SIDECAR_DIR"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"

printf '%s\n' "Starting OpenWork micro-sandbox"
printf '%s\n' "- workspace: $OPENWORK_WORKSPACE"
printf '%s\n' "- home: $HOME"
printf '%s\n' "- openwork url: http://$OPENWORK_CONNECT_HOST:$OPENWORK_PORT"
if [ "$OPENWORK_TOKEN_SOURCE" = "generated" ]; then
  printf '%s\n' "- client token (generated): $OPENWORK_TOKEN"
else
  printf '%s\n' "- client token: from OPENWORK_TOKEN"
fi
if [ "$OPENWORK_HOST_TOKEN_SOURCE" = "generated" ]; then
  printf '%s\n' "- host token (generated): $OPENWORK_HOST_TOKEN"
else
  printf '%s\n' "- host token: from OPENWORK_HOST_TOKEN"
fi
printf '%s\n' "- approval mode: $OPENWORK_APPROVAL_MODE"
printf '%s\n' "- cors origins: $OPENWORK_CORS_ORIGINS"
printf '%s\n' "- health: curl http://$OPENWORK_CONNECT_HOST:$OPENWORK_PORT/health"
printf '%s\n' "- auth test: curl -H \"Authorization: Bearer <client token>\" http://$OPENWORK_CONNECT_HOST:$OPENWORK_PORT/workspaces"

exec openwork serve \
  --workspace "$OPENWORK_WORKSPACE" \
  --remote-access \
  --openwork-port "$OPENWORK_PORT" \
  --opencode-host 127.0.0.1 \
  --opencode-port "$OPENWORK_OPENCODE_PORT" \
  --openwork-token "$OPENWORK_TOKEN" \
  --openwork-host-token "$OPENWORK_HOST_TOKEN" \
  --approval "$OPENWORK_APPROVAL_MODE" \
  --cors "$OPENWORK_CORS_ORIGINS" \
  --connect-host "$OPENWORK_CONNECT_HOST" \
  --allow-external \
  --sidecar-source external \
  --opencode-source external \
  --openwork-server-bin /usr/local/bin/openwork-server \
  --opencode-bin /usr/local/bin/opencode \
  --no-opencode-router
