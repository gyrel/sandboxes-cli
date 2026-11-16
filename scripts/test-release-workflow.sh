#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
workflow="$root/.github/workflows/m7-pretag-approval.yml"
[[ "$(grep -Ec '^  create_tag:$' "$workflow")" -eq 1 ]]
create_tag_job=$(awk '
  /^  create_tag:$/ { in_job = 1 }
  in_job && /^  [[:alnum:]_-]+:$/ && $0 != "  create_tag:" { exit }
  in_job { print }
' "$workflow")
grep -Fq '    needs: quality' <<<"$create_tag_job"
grep -Fq '      contents: write' <<<"$create_tag_job"
grep -Fq '[[ "$GITHUB_REF" == "refs/heads/main" ]]' <<<"$create_tag_job"
grep -Fq '[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]' <<<"$create_tag_job"
grep -Fq '[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]' <<<"$create_tag_job"
grep -Fq 'ref=refs/tags/$tag' <<<"$create_tag_job"
grep -Fq 'object=$GITHUB_SHA' <<<"$create_tag_job"
grep -Fq 'sha=$tag_object' <<<"$create_tag_job"
grep -Fq 'GH_TOKEN: ${{ github.token }}' <<<"$create_tag_job"
! grep -Fq 'actions/checkout' <<<"$create_tag_job"
! grep -Fq 'scripts/' <<<"$create_tag_job"
[[ "$(grep -Fc 'contents: write' "$workflow")" -eq 1 ]]
if grep -Eq -- '--force|--force-with-lease' <<<"$create_tag_job"; then
  printf 'release tag workflow must never force-update refs\n' >&2
  exit 1
fi
dispatch_job=$(awk '
  /^  dispatch_release:$/ { in_job = 1 }
  in_job && /^  [[:alnum:]_-]+:$/ && $0 != "  dispatch_release:" { exit }
  in_job { print }
' "$workflow")
grep -Fq '    needs: create_tag' <<<"$dispatch_job"
grep -Fq "if: github.repository == 'rheic/sandboxes-daemon' || github.repository == 'rheic/sandboxes-cli'" <<<"$dispatch_job"
grep -Fq 'TAG: v${{ inputs.version }}' <<<"$dispatch_job"
grep -Fq 'ref=$TAG' <<<"$dispatch_job"
! grep -Fq 'contents: write' <<<"$dispatch_job"
grep -Fq '      actions: write' <<<"$dispatch_job"
grep -Fq 'actions/workflows/release.yml/dispatches' <<<"$dispatch_job"
[[ "$(grep -Fc 'actions: write' "$workflow")" -eq 1 ]]
if [[ -f "$root/.github/workflows/release.yml" ]]; then
  grep -Fq '  workflow_dispatch:' "$root/.github/workflows/release.yml"
fi
printf 'PASS: tag write token is isolated; release dispatch has a separate minimal job\n'

release_workflow="$root/.github/workflows/release.yml"
grep -Fq 'release_tag:' "$release_workflow"
grep -Fq "github.event_name == 'workflow_dispatch' && inputs.release_tag || github.ref_name" "$release_workflow"
grep -Fq 'Mark the container workspace safe for Git' "$release_workflow"
grep -Fq 'git config --global --add safe.directory "$GITHUB_WORKSPACE"' "$release_workflow"
grep -Fq 'if [[ "$GITHUB_EVENT_NAME" == workflow_dispatch && "$GITHUB_REF" != "refs/heads/main" ]]' "$release_workflow"
grep -Fq 'git merge-base --is-ancestor "$tag_commit" origin/main' "$release_workflow"
printf 'PASS: release retry checks an explicit tag from protected main and marks only its workspace safe\n'
