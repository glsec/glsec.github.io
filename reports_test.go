// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestScreenshotSite(t *testing.T) {
	for link, want := range map[string]string{
		"https://github.com/glsec/example-github-code-scanning/pull/2/files": "GitHub",
		"https://gitlab.com/glsec-io/examples/docker/-/pipelines/1":          "GitLab",
	} {
		if got := (Screenshot{Link: link}).Site(); got != want {
			t.Errorf("Site(%q) = %q, want %q", link, got, want)
		}
	}
}
