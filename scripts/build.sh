#!/usr/bin/env bash
# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the site into _site from the latest glsec release: its docs, its
# rule list, the output of its binary on sample/.gitlab-ci.yml, and the latest GitLab
# component release. Needs git, go, curl, jq and GH_TOKEN for the GitHub API.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tag=$(gh api repos/glsec/glsec/releases/latest --jq .tag_name)
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "unexpected glsec tag: $tag" >&2; exit 1; }

component=$(curl -fsS https://gitlab.com/api/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ciCatalogResource(fullPath:\"glsec-io/glsec\"){versions(first:1){nodes{name}}}}"}' |
  jq -r '.data.ciCatalogResource.versions.nodes[0].name')
[[ $component =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "unexpected component version: $component" >&2; exit 1; }

echo "glsec $tag, component $component"
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" https://github.com/glsec/glsec.git "$work/glsec"
go build -C "$work/glsec" -o "$work/glsec-bin" ./cmd/glsec

# glsec exits 1 on the sample's error findings; anything else is a failure.
rc=0
(cd sample && "$work/glsec-bin" --no-color .gitlab-ci.yml) > "$work/sample.txt" || rc=$?
[ "$rc" -eq 1 ] || { echo "glsec exited $rc on the sample" >&2; cat "$work/sample.txt" >&2; exit 1; }

"$work/glsec-bin" list --format json > "$work/rules.json"

go run . -src "$work/glsec" -version "${tag#v}" -component "$component" -sample "$work/sample.txt" -rules "$work/rules.json" -out _site
