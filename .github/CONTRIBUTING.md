# Contributing to owLSM

We're thrilled that you're interested in contributing to owLSM!  
Whether you're fixing a bug, adding a feature, improving documentation, or just asking questions — every contribution matters and is appreciated.  
If you have any questions or need help, please don't hesitate to ask on discord or by opening an issue.

## Getting Started

1. **Fork the repository** and clone it locally
2. **Set up the development environment** — see the [README.md](../README.md) for build instructions

## How to Contribute

### Reporting Issues

- Check if the issue already exists before creating a new one
- Provide as much context as possible (Distro, kernel version, steps to reproduce, etc'). We may ask for additional info.
- Include relevant logs or error messages

### Submitting Code Changes

1. Create a branch for your changes
2. Make your changes following our coding conventions (see below)
3. Write clear, descriptive commit messages
4. Open a pull request with a detailed description of what you've done

### Contributor License Agreement (CLA)

To keep contribution flow low-friction while ensuring clear legal rights, owLSM uses an automated CLA check on pull requests.

- The first time you contribute, a bot comment will ask you to sign once.
- Individual contributors: review and sign [`CLA.md`](./CLA.md).
- Contributors submitting code owned by an employer: ensure the employer signs [`CCLA.md`](./CCLA.md) as well.
- Sign by commenting the exact phrase on your PR:
  `I have read the CLA and I hereby sign it`
- After signing, your next PRs should pass CLA automatically.

## Use cursor and other AI features:
### MCP related
**enable MCP's when needed**: go to your IDE settings and enable the relevant MCP's to the current workflow. Always enabling all the MCP's will degrade the results.<br>
**lsp-mcp**: install dependencies
```bash
go install github.com/isaacphi/mcp-language-server@latest
sudo apt install clangd
npm install -g pyright
```
**github-mcp**: Some skills/subagents require this mcp. [Guide to install](https://github.com/github/github-mcp-server)
### Subagents & skills
Use cursor version that supports [subagents](https://cursor.com/docs/context/subagents) and [skills](https://cursor.com/docs/context/skills)<br>

## Coding Conventions

owLSM has specific coding conventions documented in the [`AGENTS.md`](../AGENTS.md) file. Please read it carefully before contributing code.

### Using the Lint Agent

If you're using Cursor IDE, you can use the [lint-agent](.cursor/agents/lint-agent.md) to automatically check and fix coding convention violations. This agent:

- Enforces all conventions from `AGENTS.md`
- Fixes style issues without changing logic
- Verifies changes by building and running tests

Simply provide the paths you want to check, and the lint agent will handle the rest.

## Commit Messages

Write clear, descriptive commit messages that explain **what** you changed and **why**.

## Pull Requests

When opening a pull request:

1. **Provide a clear title** that summarizes the change
2. **Describe what the PR does** and why the change is needed
3. **Reference any related issues** (e.g., "Fixes #123")
4. **List any breaking changes** or special considerations
5. **Include test results** if applicable

### PR Checklist

- [ ] Code follows the project's coding conventions
- [ ] Changes are documented where necessary
- [ ] Tests pass locally
- [ ] Commit messages are clear and descriptive
- [ ] CLA is signed (first contribution only)

## Code Review

All submissions require review. We aim to review PRs promptly and provide constructive feedback. Don't be discouraged if changes are requested — it's part of the collaborative process!

We're here to help and want your contribution to be a positive experience. Thank you for helping make owLSM better!
