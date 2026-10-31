// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func fixture(out string) Options {
	return Options{Src: "testdata/src", Version: "1.23.0", Component: "v1.0.25", Reports: "testdata/reports", Rules: "testdata/rules.json", Bench: "testdata/bench.jsonl", Tags: "testdata/tags.json", Out: out}
}

func buildFixture(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "_site")
	if err := build(fixture(out)); err != nil {
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
	for _, p := range []string{"index.html", "404.html", "owasp/index.html", "reports/index.html", "performance/index.html", "rules/index.html", "rules/GL001/index.html", "rules/GL002/index.html", "style.css", "favicon.ico", "favicon-32.png", "favicon-64.png", "apple-touch-icon.png", "logo.png", "sitemap.xml", "robots.txt"} {
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
		`<pre tabindex="0"><code class="language-yaml">`,
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
		`<span class="line" style="--i: 0"><span class="ansi-red">error</span>[<span class="ansi-bold">GL001</span>]: &lt;sample&gt; &amp; more</span>`,
		`<span class="line" style="--i: 1">  --&gt; .gitlab-ci.yml:6:10</span>`,
		"<strong>3/10</strong>OWASP CI/CD risks",
		"gitlab.com/glsec-io/glsec/glsec@v1.0.25",
		"ghcr.io/glsec/glsec:1.23.0",
		"releases/download/v1.23.0/glsec_1.23.0_linux_amd64.tar.gz",
		"/plugin install glsec@glsec",
		"brew install glsec/tap/glsec",
		"aqua g -i glsec/glsec",
		"mise use github:glsec/glsec",
		"pipx install glsec",
		`<a href="https://gitlab.com/explore/catalog/glsec-io/glsec">GitLab</a>`,
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
	for name, edit := range map[string]func(*Options){
		"no version":       func(o *Options) { o.Version = "" },
		"bad version":      func(o *Options) { o.Version = "1.23" },
		"bad component":    func(o *Options) { o.Component = "1.0.25" },
		"no reports":       func(o *Options) { o.Reports = "testdata/missing" },
		"no rule list":     func(o *Options) { o.Rules = "testdata/missing.json" },
		"rule list broken": func(o *Options) { o.Rules = "testdata/reports/text.txt" },
		"no rules in tree": func(o *Options) { o.Src = "testdata" },
	} {
		o := fixture(filepath.Join(t.TempDir(), "o"))
		edit(&o)
		if err := build(o); err == nil {
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
	rules := filepath.Join(src, "rules.json")
	if err := os.WriteFile(rules, []byte(`[{"id":"GL001","owasp":["CICD-SEC-3"]}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	o := fixture(filepath.Join(t.TempDir(), "o"))
	o.Src, o.Rules = src, rules
	err := build(o)
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

func TestBuild_OWASPPage(t *testing.T) {
	page := read(t, filepath.Join(buildFixture(t), "owasp", "index.html"))
	for _, want := range []string{
		"rules cover 3 of the ten",
		"The remaining 2 depend on settings",
		"no rule yet",
		`id="cicd-sec-3"`,
		`<a href="/rules/GL001/"><span class="rid">GL001</span> Mutable image tag</a>`,
		`<a href="/rules/GL011/"><span class="rid">GL011</span>`,
		"2 rules",
		"1 rule<",
		`href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-And-Visibility"`,
		"not in the pipeline file",
		`aria-current="page">OWASP</a>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("OWASP page lacks %s", want)
		}
	}
	// GL002 is listed under both of its risks.
	if n := strings.Count(page, `href="/rules/GL002/"`); n != 2 {
		t.Errorf("GL002 is listed %d times, want 2", n)
	}
}

func TestLoadRisks_Rejects(t *testing.T) {
	ids := []string{"GL001", "GL002"}
	for name, body := range map[string]string{
		"unknown category":                 `[{"id":"GL001","owasp":["CICD-SEC-11"]},{"id":"GL002","owasp":["CICD-SEC-3"]}]`,
		"no category":                      `[{"id":"GL001","owasp":[]},{"id":"GL002","owasp":["CICD-SEC-3"]}]`,
		"rule without doc":                 `[{"id":"GL001","owasp":["CICD-SEC-3"]},{"id":"GL002","owasp":["CICD-SEC-3"]},{"id":"GL003","owasp":["CICD-SEC-3"]}]`,
		"documented, unlisted":             `[{"id":"GL001","owasp":["CICD-SEC-3"]}]`,
		"rules for a risk without summary": `[{"id":"GL001","owasp":["CICD-SEC-2"]},{"id":"GL002","owasp":["CICD-SEC-3"]}]`,
	} {
		path := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := loadRisks(path, ids); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOWASPRisks(t *testing.T) {
	if len(owaspRisks) != 10 {
		t.Fatalf("%d risks, want 10", len(owaspRisks))
	}
	for i, r := range owaspRisks {
		if want := fmt.Sprintf("CICD-SEC-%d", i+1); r.ID != want {
			t.Errorf("risk %d is %s, want %s", i, r.ID, want)
		}
		if want := fmt.Sprintf("%sCICD-SEC-%02d-", owaspBase, i+1); !strings.HasPrefix(r.URL, want) {
			t.Errorf("%s: URL %s", r.ID, r.URL)
		}
		if (r.Summary == "") == (r.Outside == "") {
			t.Errorf("%s needs exactly one of Summary and Outside", r.ID)
		}
	}
}

func TestBuild_ReportsPage(t *testing.T) {
	page := read(t, filepath.Join(buildFixture(t), "reports", "index.html"))
	for _, want := range []string{
		"what glsec 1.23.0 prints for this file, regenerated with every release",
		`<pre class="numbered" tabindex="0"><code><span class="ln">deploy:</span>` + "\n" + `<span class="ln">  image: alpine:latest</span>`,
		`<section class="report" id="codeclimate">`,
		"codeclimate output &lt;x&gt;",
		"codequality: gl-code-quality.json",
		"name: ghcr.io/glsec/glsec:1.23.0",
		"junit: glsec-junit.xml",
		`<a href="#sarif">SARIF</a>`,
		`<img src="/screenshots/code-quality-mr.png"`,
		`<img src="/screenshots/junit-tests.png"`,
		"expire_in: 30 days",
		`aria-current="page">Reports</a>`,
		`<a href="#gitlab-sast">GitLab SAST</a>`,
		"sast: gl-sast-report.json",
		"--format gitlab-sast --no-exit-codes",
		`<section class="report" id="template">`,
		"<code>docs/templates/mr-comment.md.tmpl</code>",
		"template output &lt;x&gt;",
		`<a href="#inventory">Pipeline inventory</a>`,
		`<section class="report" id="inventory">`,
		`<span class="ln">    ref: main</span>`,
		"glsec 1.23.0 lists these components.",
		`&#34;purl&#34;: &#34;pkg:docker/library/redis@7.4.1&#34;`,
		"blob/v1.23.0/docs/ci-integration.md#pipeline-inventory-cyclonedx",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("reports page lacks %s", want)
		}
	}
	if strings.Contains(page, "{{VERSION}}") {
		t.Error("reports page has an unreplaced version")
	}
	// Formats GitLab doesn't read as a report get no wiring.
	if n := strings.Count(page, "Job that publishes it"); n != 3 {
		t.Errorf("%d wiring snippets, want 3", n)
	}
}

func TestLoadReports_RejectsEmptyOutput(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"input.yml", "text.txt", "table.txt", "codeclimate.txt", "junit.txt", "sarif.txt", "gitlab-sast.txt", "template.txt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "json.txt"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadReports(dir, "1.23.0"); err == nil || !strings.Contains(err.Error(), "json") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadInventory_RejectsOtherJSON(t *testing.T) {
	for name, bom := range map[string]string{
		"not JSON":         "x",
		"not CycloneDX":    `{"bomFormat":"SPDX","components":[{}]}`,
		"no components":    `{"bomFormat":"CycloneDX"}`,
		"empty components": `{"bomFormat":"CycloneDX","components":[]}`,
	} {
		dir := t.TempDir()
		for f, data := range map[string]string{"inventory.yml": "x\n", "inventory.json": bom} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := loadInventory(dir); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// The header's link colours are light-on-slate; scoped to the header, they
// can't make other nav elements, such as the formats on /reports/, unreadable.
func TestHeaderNavStylesAreScoped(t *testing.T) {
	css := read(t, filepath.Join("static", "style.css"))
	for _, line := range strings.Split(css, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "nav ") || strings.HasPrefix(strings.TrimSpace(line), "nav a") {
			t.Errorf("unscoped nav rule: %s", strings.TrimSpace(line))
		}
	}
}

// Nothing in a doc can put markup or a script URL on a page: raw HTML is
// dropped and links with a script or data scheme lose their href. Both come
// from goldmark's defaults, which these tests pin (#32).
func TestConvert_NoScript(t *testing.T) {
	src := strings.Join([]string{
		"# GL999",
		"",
		"<script>alert(1)</script>",
		"",
		`<img src=x onerror="alert(1)">`,
		"",
		"Inline <span onmouseover=\"alert(1)\">html</span> and <a href=\"javascript:alert(1)\">a</a>.",
		"",
		"[a](javascript:alert(1)) [b](JavaScript:alert(1)) [c](  javascript:alert(1)) [d](javascript://%0aalert(1))",
		"[e](vbscript:msgbox) [f](data:text/html,<script>alert(1)</script>) [g](JAVASCRIPT&#58;alert(1))",
		"![h](javascript:alert(1)) <javascript:alert(1)> [i][ref]",
		"",
		"[ref]: javascript:alert(1)",
		"",
		"| a | b |",
		"|---|---|",
		"| `x|y` | <b onclick=alert(1)>c</b> |",
	}, "\n")
	html, err := converter{version: "1.23.0"}.convert("docs/rules/GL999.md", []byte(src), true)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.ToLower(string(html))
	for _, bad := range []string{"<script", "<img src=x", "onerror", "onmouseover", "onclick", "<span", `href="javascript`, `href="vbscript`, `href="data:`, `src="javascript`, "javascript&#58;"} {
		if strings.Contains(out, bad) {
			t.Errorf("rendered doc contains %q:\n%s", bad, html)
		}
	}
	if !strings.Contains(out, "raw html omitted") {
		t.Errorf("expected goldmark to drop raw HTML, got:\n%s", html)
	}
}

// Every page carries the CSP and loads nothing it forbids: no script, and
// images and stylesheets only from the site itself (#32).
func TestBuild_ContentSecurityPolicy(t *testing.T) {
	out := buildFixture(t)
	const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'">`
	srcRe := regexp.MustCompile(`<img[^>]*src="(https?:)?//|<link rel="(?:stylesheet|icon|apple-touch-icon)"[^>]*href="(https?:)?//`)
	pages := 0
	err := filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		pages++
		page := read(t, p)
		if !strings.Contains(page, csp) {
			t.Errorf("%s lacks the CSP meta tag", p)
		}
		if i, j := strings.Index(page, csp), strings.Index(page, "<link"); j >= 0 && i > j {
			t.Errorf("%s: the CSP comes after the first <link>", p)
		}
		for _, bad := range []string{"<script", "<iframe", "<object", "<embed", "<form", "<base"} {
			if strings.Contains(page, bad) {
				t.Errorf("%s contains %s, which the CSP blocks or forbids", p, bad)
			}
		}
		if m := srcRe.FindString(page); m != "" {
			t.Errorf("%s loads a resource from another origin: %s", p, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if pages < 5 {
		t.Fatalf("checked %d pages, want the whole site", pages)
	}
}
