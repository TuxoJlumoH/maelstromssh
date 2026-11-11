#!/usr/bin/env bash
# Installs desktop-file-utils for the packaging lint job.
#
# Ubuntu package mirrors on the GitHub runners are occasionally unreachable,
# so retry instead of failing the job on a transient DNS error.
set -euo pipefail

for attempt in 1 2 3 4 5; do
  if sudo apt-get update -o Acquire::Retries=5 &&
    sudo apt-get install -y -o Acquire::Retries=5 desktop-file-utils; then
    exit 0
  fi
  echo "apt attempt ${attempt} failed, retrying in 15s" >&2
  sleep 15
done

echo "apt failed after 5 attempts" >&2
exit 1
