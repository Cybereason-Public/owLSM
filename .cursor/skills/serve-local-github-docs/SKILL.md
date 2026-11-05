---
name: serve-local-github-docs
description: Starts the local owLSM GitHub Pages site at http://127.0.0.1:4000/owLSM/. Use when the user wants local GitHub docs, a Jekyll preview, localhost:4000, or to preview docs/GithubPages edits in a browser.
---

# Serve local GitHub docs

Run this script. Do not invent another Jekyll command.

```bash
.cursor/skills/serve-local-github-docs/scripts/serve.sh
```

The process stays in the foreground. Start it in the background if it is not already running. Wait until `http://127.0.0.1:4000/owLSM/` responds, or until the script prints that it is already available.

If an old Jekyll is already on port 4000 without `--force_polling`, the script restarts it. That flag is required: Cursor saves are often missed by inotify, so the page never updates on refresh.

## After it is up

Tell the user:

http://127.0.0.1:4000/owLSM/

`docs/GithubPages/_config.yml` sets `baseurl: /owLSM`. The site root is `/owLSM/`, not `/`.

Preview loop:

1. Edit files under `docs/GithubPages/` (that is the site source, not `Plan/`).
2. Save to disk. Jekyll does not see unsaved editor buffers.
3. Wait about 2 seconds, then refresh.

Laptop browser and the Cursor browser both work via localhost. Do not start a Cloudflare tunnel unless the user asks for a public URL.
