# Contributing — ThreatHunt

Thanks for your interest in contributing to ThreatHunt. This document covers how to set up your environment, the branching strategy and the pull request process.

---

## Getting started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/your-username/threathunt.git
   cd threathunt
   ```
3. **Set up** the development environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   docker-compose up -d
   cp .env.example .env
   python run.py
   ```

---

## Branching strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, production-ready code |
| `dev` | Active development — base branch for all PRs |
| `feature/tool-name` | New OSINT tool integration |
| `fix/issue-description` | Bug fixes |
| `docs/section-name` | Documentation updates |

Always branch off `dev`, never directly off `main`.

```bash
git checkout dev
git pull origin dev
git checkout -b feature/your-feature-name
```

---

## Adding a new OSINT tool

1. Create your tool class in `automated_recon/tools/your_tool.py`:

```python
class YourTool:
    def __init__(self, target: str, api_key: str = None):
        self.target = target
        self.api_key = api_key

    def run(self) -> dict:
        # Your tool logic here
        return {
            "tool": "your_tool",
            "target": self.target,
            "results": [...]
        }
```

2. Register the tool in `automated_recon/mainMongo.py` tool selection logic
3. Add it to the tool list in the API (`GET /api/tools` endpoint)
4. Document it in `docs/tools.md`

---

## Pull request process

1. Make sure your branch is up to date with `dev`:
   ```bash
   git fetch origin
   git rebase origin/dev
   ```
2. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
3. Open a PR against `dev` on GitHub
4. Fill in the PR template — describe what changed and why
5. Wait for review from a maintainer

---

## Code style

- Python: follow PEP 8. Use meaningful variable names.
- Each tool class should be self-contained with no side effects outside its `run()` method
- Log errors using the project's `logging` module, not `print()`
- Never commit API keys, `.env` files or credentials

---

## Reporting bugs

Open a GitHub Issue with:
- What you were doing
- What you expected to happen
- What actually happened
- Steps to reproduce
- Environment (OS, Python version, relevant tool versions)

---

## License

By contributing, you agree that your contributions will be licensed under the same MIT License that covers this project.
