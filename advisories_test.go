// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuild_AttacksPage(t *testing.T) {
	out := buildFixture(t)
	page := read(t, filepath.Join(out, "attacks", "index.html"))
	for _, want := range []string{
		"<title>Known attacks and what glsec sees of them · glsec</title>",
		`aria-current="page">Attacks</a>`,
		"glsec detects the configuration shape an attack used",
		"Bugs in GitLab itself are left out.",
		`<a href="https://www.cve.org/CVERecord?id=CVE-2099-0002">CVE-2099-0002</a>`,
		`<a href="/rules/GL011/"><span class="rid">GL011</span> `,
		`<span class="sev">error</span>`,
		"partly detected",
		`<a href="https://github.com/glsec/glsec/issues/9001">Tracking issue</a>`,
		"visible in the pipeline file, not reported yet.",
		`id="not-detected"`,
		"needs run-time state that a file scan can&#39;t see.",
		`Also known as <a href="https://github.com/advisories/GHSA-2222-3333-4444">GHSA-2222-3333-4444</a>.`,
		"Fixed in 2.0.1.",
		"the same attack class in GitLab CI",
		`<span class="seen">Reported by <a href="/rules/GL082/"><span class="rid">GL082</span></a>.</span>`,
		`<span class="unseen">Not seen: needs run-time state`,
		`href="https://github.com/glsec/glsec/blob/v1.23.0/docs/advisories.yml"`,
		`id="cve-2099-0002"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("attacks page lacks %s", want)
		}
	}
	// The sections keep the file's order within them, and a campaign isn't
	// listed among the detected CVEs.
	detected := page[strings.Index(page, `id="detected"`):strings.Index(page, `id="not-detected"`)]
	if strings.Index(detected, "CVE-2099-0001") > strings.Index(detected, "CVE-2099-0002") || strings.Contains(detected, "Example Worm") {
		t.Errorf("detected section:\n%s", detected)
	}
	// A campaign says what it misses in its steps, not again below them.
	campaign := page[strings.Index(page, `id="example-worm"`):]
	campaign = campaign[:strings.Index(campaign, "</section>")]
	if n := strings.Count(campaign, "Not seen"); n != 1 || strings.Contains(campaign, `class="risk-rules"`) {
		t.Errorf("campaign repeats its steps (%d × Not seen):\n%s", n, campaign)
	}
	if !strings.Contains(read(t, filepath.Join(out, "sitemap.xml")), "https://glsec.github.io/attacks/") {
		t.Error("attacks page is not in the sitemap")
	}
	if !strings.Contains(read(t, filepath.Join(out, "index.html")), `<a href="/attacks/">Attacks</a>`) {
		t.Error("menu lacks the attacks page")
	}
}

// A release from before docs/advisories.yml builds as before: no page, no
// menu entry, nothing in the sitemap.
func TestBuild_NoAdvisoriesFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.CopyFS(src, os.DirFS("testdata/src")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(src, "docs", "advisories.yml")); err != nil {
		t.Fatal(err)
	}
	o := fixture(filepath.Join(t.TempDir(), "_site"))
	o.Src = src
	if err := build(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(o.Out, "attacks")); !os.IsNotExist(err) {
		t.Errorf("attacks page built without the file: %v", err)
	}
	if strings.Contains(read(t, filepath.Join(o.Out, "index.html")), "/attacks/") || strings.Contains(read(t, filepath.Join(o.Out, "sitemap.xml")), "/attacks/") {
		t.Error("menu or sitemap links the missing page")
	}
}

func TestLoadAdvisories_Rejects(t *testing.T) {
	ids := []string{"GL001", "GL002"}
	const ok = "- id: CVE-2099-0001\n  kind: cve\n  product: P\n  summary: S\n  coverage: full\n  rules: [{rule: GL001, severity: warn}]\n"
	for name, body := range map[string]string{
		"not yaml":                "- id: [\n",
		"empty":                   "# nothing\n",
		"unknown key":             ok + "  severity: high\n",
		"unknown rule":            strings.Replace(ok, "GL001", "GL999", 1),
		"unknown kind":            strings.Replace(ok, "kind: cve", "kind: bug", 1),
		"id not a CVE":            strings.Replace(ok, "CVE-2099-0001", "BUG-1", 1),
		"no summary":              strings.Replace(ok, "summary: S", "summary: ''", 1),
		"unknown coverage":        strings.Replace(ok, "coverage: full", "coverage: most", 1),
		"no rules":                strings.Replace(ok, "  rules: [{rule: GL001, severity: warn}]\n", "", 1),
		"partial without reason":  strings.Replace(ok, "coverage: full", "coverage: partial", 1),
		"full with reason":        ok + "  reason: by-design\n",
		"no-rule-yet, no issue":   strings.Replace(ok, "coverage: full", "coverage: partial", 1) + "  reason: no-rule-yet\n",
		"listed twice":            ok + ok,
		"campaign without steps":  "- id: Worm\n  kind: campaign\n  product: P\n  summary: S\n  coverage: none\n  reason: not-static\n",
		"step with rule and none": "- id: Worm\n  kind: campaign\n  product: P\n  summary: S\n  coverage: none\n  reason: not-static\n  steps: [{step: A}]\n",
		"step with unknown rule":  "- id: Worm\n  kind: campaign\n  product: P\n  summary: S\n  coverage: none\n  reason: not-static\n  steps: [{step: A, rules: [GL999]}]\n",
		"steps outside campaign":  ok + "  steps: [{step: A, rules: [GL001]}]\n",
	} {
		src := t.TempDir()
		if err := os.MkdirAll(filepath.Join(src, "docs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "docs", "advisories.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAdvisories(src, ids); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The build fails on a rule the release doesn't have, before writing pages
// that would link to it.
func TestBuild_RejectsAdvisoryWithUnknownRule(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.CopyFS(src, os.DirFS("testdata/src")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(src, "docs", "advisories.yml")
	data := strings.Replace(read(t, file), "rule: GL011", "rule: GL099", 1)
	if err := os.WriteFile(file, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	o := fixture(filepath.Join(t.TempDir(), "_site"))
	o.Src = src
	if err := build(o); err == nil || !strings.Contains(err.Error(), "GL099") {
		t.Errorf("err = %v", err)
	}
}

// A CVE links to cve.org, a GHSA to the Advisory Database or its repository.
func TestAdvisoryURL(t *testing.T) {
	for _, c := range []struct {
		a    Advisory
		want string
	}{
		{Advisory{ID: "CVE-2025-30066"}, "https://www.cve.org/CVERecord?id=CVE-2025-30066"},
		{Advisory{ID: "GHSA-7x29-qqmq-v6qc"}, "https://github.com/advisories/GHSA-7x29-qqmq-v6qc"},
		{Advisory{ID: "GHSA-7x29-qqmq-v6qc", Repo: "o/r"}, "https://github.com/o/r/security/advisories/GHSA-7x29-qqmq-v6qc"},
		{Advisory{ID: "Shai-Hulud"}, ""},
	} {
		if got := c.a.URL(); got != c.want {
			t.Errorf("%s: %q, want %q", c.a.ID, got, c.want)
		}
	}
}
