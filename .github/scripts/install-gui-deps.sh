#!/usr/bin/env bash
# Installs the system libraries the GUI crate needs to build.
#
# GitHub's Ubuntu runners occasionally fail to resolve archive.ubuntu.com or
# azure.archive.ubuntu.com, which makes a single apt run fail through no fault
# of the project. Retry a few times before giving up.
set -euo pipefail

packages=(
  libxkbcommon-dev
  libwayland-dev
  libxcb-render0-dev
  libxcb-shape0-dev
  libxcb-xfixes0-dev
)

for attempt in 1 2 3 4 5; do
  if sudo apt-get update -o Acquire::Retries=5 &&
    sudo apt-get install -y -o Acquire::Retries=5 "${packages[@]}"; then
    exit 0
  fi
  echo "apt attempt ${attempt} failed, retrying in 15s" >&2
  sleep 15
done

echo "apt failed after 5 attempts" >&2
exit 1
