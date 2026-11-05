#!/usr/bin/env bash
set -euo pipefail

PORT=4000
URL="http://127.0.0.1:${PORT}/owLSM/"
JEKYLL_CMD=(bundle exec jekyll serve --host 0.0.0.0 --port "$PORT" --livereload --force_polling)

find_repo_root() {
  local dir
  dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  while [[ "$dir" != "/" ]]; do
    if [[ -f "$dir/docs/GithubPages/_config.yml" ]]; then
      printf '%s\n' "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}

docs_are_up() {
  curl -fsS --max-time 2 -o /dev/null "$URL"
}

port_in_use() {
  command -v ss >/dev/null 2>&1 && ss -ltn "( sport = :${PORT} )" | grep -q LISTEN
}

jekyll_uses_polling() {
  pgrep -af "jekyll serve" | grep -q -- "--force_polling"
}

stop_jekyll() {
  pkill -f "jekyll serve" 2>/dev/null || true
  local i
  for i in $(seq 1 20); do
    if ! port_in_use; then
      return 0
    fi
    sleep 0.25
  done
  echo "Port ${PORT} did not free after stopping Jekyll." >&2
  exit 1
}

repo_root="$(find_repo_root)" || {
  echo "Could not find docs/GithubPages/_config.yml" >&2
  exit 1
}

site_dir="${repo_root}/docs/GithubPages"

if docs_are_up && jekyll_uses_polling; then
  echo "Local GitHub docs already available at ${URL}"
  exit 0
fi

if port_in_use; then
  if docs_are_up || pgrep -af "jekyll serve" | grep -qv grep; then
    echo "Restarting Jekyll with --force_polling so saved edits are picked up"
    stop_jekyll
  else
    echo "Port ${PORT} is in use, but ${URL} is not serving the docs." >&2
    exit 1
  fi
fi

if ! command -v bundle >/dev/null 2>&1; then
  echo "bundle is required (Ruby Bundler)." >&2
  exit 1
fi

cd "$site_dir"
if ! bundle check >/dev/null 2>&1; then
  bundle install
fi

echo "Serving local GitHub docs at ${URL}"
exec "${JEKYLL_CMD[@]}"
