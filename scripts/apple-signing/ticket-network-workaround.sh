#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != macOS ]]; then
    echo 'Ticket networking may only be changed on a GitHub-hosted macOS runner.' >&2
    exit 1
fi
# Opt-in workaround for https://github.com/actions/runner-images/issues/14924.
# The disposable VM retains this rule for the remainder of the job.
echo 'block return out quick proto udp from any to any port 443' | sudo pfctl -f -
sudo pfctl -E
