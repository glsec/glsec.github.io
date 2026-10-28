#!/usr/bin/env bash
# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the site into _site from the latest glsec release: its docs, its
# rule list, the output of its binary on sample/bad-pipeline.yml in every format,
# and the latest GitLab
# component release. The performance page reads the benchmark history from
# glsec's benchmarks branch and the tags that mark releases in it.
# Needs git, go, curl, jq and GH_TOKEN for the GitHub API.
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

# The sample in every output format. glsec exits 1 on the sample's error
# findings; anything else is a failure.
mkdir "$work/reports"
cp sample/bad-pipeline.yml "$work/reports/input.yml"
for format in text table codeclimate junit sarif json; do
  rc=0
  # Text and table keep glsec's terminal colours; the site turns them into
  # spans. The machine-readable formats have none.
  color=--no-color
  case "$format" in text | table) color= ;; esac
  (cd sample && FORCE_COLOR=1 "$work/glsec-bin" $color --format "$format" bad-pipeline.yml) > "$work/reports/$format.txt" || rc=$?
  [ "$rc" -eq 1 ] || { echo "glsec --format $format exited $rc on the sample" >&2; cat "$work/reports/$format.txt" >&2; exit 1; }
done

"$work/glsec-bin" list --format json > "$work/rules.json"

curl -fsSL https://raw.githubusercontent.com/glsec/glsec/benchmarks/data/benchmarks.jsonl -o "$work/benchmarks.jsonl"
gh api --paginate repos/glsec/glsec/tags --jq '.[] | {name, sha: .commit.sha}' | jq -s . > "$work/tags.json"

go run . -src "$work/glsec" -version "${tag#v}" -component "$component" -reports "$work/reports" -rules "$work/rules.json" \
  -bench "$work/benchmarks.jsonl" -tags "$work/tags.json" -out _site
