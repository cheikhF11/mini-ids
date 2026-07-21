#!/usr/bin/env bash
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
echo "Hooks installed: pytest -q + gitleaks protect --staged will run on every commit."
