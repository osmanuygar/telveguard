#!/usr/bin/env bash
# ContextForge'u "yumuşak fork" olarak kurar.
#   1) GitHub'da IBM/mcp-context-forge'u kendi org'unuza fork'layın (ör. telveguard/contextforge)
#   2) FORK_URL=... ./scripts/fork_setup.sh
set -euo pipefail
FORK_URL=${FORK_URL:?"FORK_URL ayarlayın, ör. git@github.com:telveguard/contextforge.git"}
UPSTREAM_URL=https://github.com/IBM/mcp-context-forge.git
DIR=${DIR:-../contextforge}

git clone "$FORK_URL" "$DIR"
cd "$DIR"
git remote add upstream "$UPSTREAM_URL"
git fetch upstream --tags

# main = upstream'in birebir aynası (asla elle commit yok)
# telveguard/main = sadece patches/ altındaki küçük, upstream'e PR'lanacak değişiklikler
git checkout -b telveguard/main upstream/main
echo "Hazır. Senkron için: git fetch upstream && git rebase upstream/main telveguard/main"
