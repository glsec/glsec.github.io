// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildFixture(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "_site")
	if err := build("testdata/src", "1.23.0", "v1.0.25", "testdata/sample.txt", out); err != nil {
		t.Fatal(err)
	}
	return out
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test reads its own output
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBuild_Pages(t *testing.T) {
	out := buildFixture(t)
	for _, p := range []string{"index.html", "404.html", "rules/index.html", "rules/GL001/index.html", "rules/GL002/index.html", "style.css", "favicon.svg", "sitemap.xml", "robots.txt"} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Errorf("missing %s", p)
		}
	}
	sitemap := read(t, filepath.Join(out, "sitemap.xml"))
	if !strings.Contains(sitemap, "https://glsec.github.io/rules/GL002/") || strings.Contains(sitemap, "404") {
		t.Errorf("sitemap:\n%s", sitemap)
	}
}

func TestBuild_RulePage(t *testing.T) {
	page := read(t, filepath.Join(buildFixture(t), "rules", "GL001", "index.html"))
	for _, want := range []string{
		"<title>GL001: Mutable image tag · glsec</title>",
		`<span class="rule-id">GL001</span> Mutable <code>image</code> tag</h1>`,
		`href="/rules/GL002/#safe-alternative"`,
		`href="/rules/"`,
		`href="https://github.com/glsec/glsec/blob/v1.23.0/README.md#shellcheck-integration"`,
		`href="https://github.com/glsec/glsec/blob/v1.23.0/rules/gl001.go"`,
		`<link rel="canonical" href="https://glsec.github.io/rules/GL001/">`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("GL001 page lacks %s", want)
		}
	}
	// Raw HTML in a doc never reaches the page.
	for _, bad := range []string{"<script", "schema: skip", "# GL001"} {
		if strings.Contains(page, bad) {
			t.Errorf("GL001 page contains %q", bad)
		}
	}
}

func TestBuild_HomeAndOverview(t *testing.T) {
	out := buildFixture(t)
	home := read(t, filepath.Join(out, "index.html"))
	for _, want := range []string{
		"error[GL001]: &lt;sample&gt; &amp; more",
		"gitlab.com/glsec-io/glsec/glsec@v1.0.25",
		"ghcr.io/glsec/glsec:1.23.0",
		"releases/download/v1.23.0/glsec_1.23.0_linux_amd64.tar.gz",
		"3 rules",
	} {
		if !strings.Contains(home, want) {
			t.Errorf("home page lacks %s", want)
		}
	}
	overview := read(t, filepath.Join(out, "rules", "index.html"))
	if !strings.Contains(overview, `<a href="/rules/GL001/">GL001</a>`) || strings.Contains(overview, "glsec Rules</h1>") {
		t.Errorf("overview:\n%s", overview)
	}
}

func TestBuild_Rejects(t *testing.T) {
	for name, args := range map[string][4]string{
		"no version":       {"testdata/src", "", "v1.0.25", "testdata/sample.txt"},
		"bad version":      {"testdata/src", "1.23", "v1.0.25", "testdata/sample.txt"},
		"bad component":    {"testdata/src", "1.23.0", "1.0.25", "testdata/sample.txt"},
		"no sample":        {"testdata/src", "1.23.0", "v1.0.25", "testdata/missing.txt"},
		"no rules in tree": {"testdata", "1.23.0", "v1.0.25", "testdata/sample.txt"},
	} {
		if err := build(args[0], args[1], args[2], args[3], filepath.Join(t.TempDir(), "o")); err == nil {
			t.Errorf("%s: build succeeded", name)
		}
	}
}

func TestBuild_RejectsBadTitle(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "docs", "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "docs", "rules.md"), []byte("# Rules\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "docs", "rules", "GL001.md"), []byte("# GL002 — Wrong id\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := build(src, "1.23.0", "v1.0.25", "testdata/sample.txt", filepath.Join(t.TempDir(), "o"))
	if err == nil || !strings.Contains(err.Error(), "first line") {
		t.Errorf("err = %v", err)
	}
}

func TestLinkFixer(t *testing.T) {
	for _, c := range []struct{ file, dest, want string }{
		{"docs/rules/GL001.md", "GL002.md", "/rules/GL002/"},
		{"docs/rules/GL001.md", "GL002.md#notes", "/rules/GL002/#notes"},
		{"docs/rules/GL001.md", "../rules.md", "/rules/"},
		{"docs/rules/GL001.md", "../../README.md#x", "https://github.com/glsec/glsec/blob/v1.23.0/README.md#x"},
		{"docs/rules.md", "rules/GL005.md", "/rules/GL005/"},
		{"docs/rules.md", "#credential-hygiene", "#credential-hygiene"},
		{"docs/rules.md", "https://owasp.org/x", "https://owasp.org/x"},
		{"docs/rules.md", "mailto:a@b.c", "mailto:a@b.c"},
	} {
		f := &linkFixer{file: c.file, version: "1.23.0"}
		got, err := f.fix(c.dest)
		if err != nil || got != c.want {
			t.Errorf("%s: fix(%q) = %q, %v; want %q", c.file, c.dest, got, err, c.want)
		}
	}
	f := &linkFixer{file: "docs/rules.md", version: "1.23.0"}
	if _, err := f.fix("../../etc/passwd"); err == nil {
		t.Error("a link out of the repository was accepted")
	}
}

func TestCheckLinks(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "index.html"), []byte(`<a href="/rules/GL999/">x</a><a href="/#install">y</a>`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := checkLinks(out)
	if err == nil || !strings.Contains(err.Error(), "/rules/GL999/") || strings.Contains(err.Error(), "install") {
		t.Errorf("err = %v", err)
	}
}
