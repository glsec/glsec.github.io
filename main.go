// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Command site builds glsec.github.io from a glsec source tree: a home page,
// the rule overview from docs/rules.md and one page per docs/rules/GLxxx.md.
//
//	go run . -src ../glsec -version 1.23.0 -component v1.0.25 -reports reports -rules rules.json \
//		-bench benchmarks.jsonl -tags tags.json -out _site
package main

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

const (
	siteURL = "https://glsec.github.io"
	repoURL = "https://github.com/glsec/glsec"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var (
	ruleFileRe = regexp.MustCompile(`^docs/rules/(GL[0-9]{3})\.md$`)
	versionRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	// The first line of a rule doc: "# GL001 — Mutable image tag".
	ruleTitleRe = regexp.MustCompile(`^# (GL[0-9]{3}) \S+ (.+)$`)
)

// Rule is one rule page.
type Rule struct {
	ID        string
	Title     string // plain text, for <title>
	TitleHTML template.HTML
	Body      template.HTML
}

// Page is what every template gets.
type Page struct {
	Title       string
	Description string
	Path        string // site path, "/" or "/rules/GL001/"
	Version     string
	Component   string
	Sample      []template.HTML // lines of the home page example
	Reports     []Report
	Input       []string // lines of the file the reports are for
	Inventory   *Inventory
	Risks       []Risk
	Covered     int // OWASP risks with at least one rule
	Outside     int // OWASP risks a pipeline file can't show
	Body        template.HTML
	Rule        *Rule
	RuleCount   int
	Perf        *Perf
}

func main() {
	src := flag.String("src", "", "glsec source tree, checked out at a release tag")
	version := flag.String("version", "", "glsec release the source tree is at, e.g. 1.23.0")
	component := flag.String("component", "", "latest GitLab component release, e.g. v1.0.25")
	reports := flag.String("reports", "", "directory with glsec's output on the sample, one <format>.txt per format, and the inventory of sample/inventory.yml")
	rules := flag.String("rules", "", "output of glsec list --format json from the same release")
	bench := flag.String("bench", "", "data/benchmarks.jsonl from glsec's benchmarks branch")
	tags := flag.String("tags", "", "glsec's tags as a JSON list of {name, sha}")
	out := flag.String("out", "_site", "output directory")
	flag.Parse()
	if err := build(Options{Src: *src, Version: *version, Component: *component, Reports: *reports, Rules: *rules, Bench: *bench, Tags: *tags, Out: *out}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// Options are the generator's inputs.
type Options struct {
	Src, Version, Component, Reports, Rules, Bench, Tags, Out string
}

func build(o Options) error {
	src, version, component, out := o.Src, o.Version, o.Component, o.Out
	if src == "" || !versionRe.MatchString(version) || !versionRe.MatchString(strings.TrimPrefix(component, "v")) || !strings.HasPrefix(component, "v") {
		return errors.New("-src, -version (X.Y.Z) and -component (vX.Y.Z) are required")
	}
	input, reports, err := loadReports(o.Reports, version)
	if err != nil {
		return err
	}
	inventory, err := loadInventory(o.Reports)
	if err != nil {
		return err
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{"lower": strings.ToLower, "thousands": thousands}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	conv := converter{version: version}

	ids, err := ruleIDs(src)
	if err != nil {
		return err
	}
	risks, covered, outside, err := loadRisks(o.Rules, ids)
	if err != nil {
		return err
	}
	perf, err := loadPerf(o.Bench, o.Tags)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}

	var urls []string
	write := func(p Page, name string) error {
		p.Version, p.Component, p.RuleCount = version, component, len(ids)
		dir := out
		if name != "404.html" {
			dir = filepath.Join(out, filepath.FromSlash(strings.Trim(p.Path, "/")))
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, p); err != nil {
			return fmt.Errorf("%s: %w", p.Path, err)
		}
		if name != "404.html" {
			urls = append(urls, siteURL+p.Path)
		}
		file := "index.html"
		if name == "404.html" {
			file = "404.html"
		}
		return os.WriteFile(filepath.Join(dir, file), buf.Bytes(), 0o644)
	}

	if err := write(Page{
		Title:       "glsec: security linter for GitLab CI/CD",
		Description: fmt.Sprintf("glsec finds security problems in .gitlab-ci.yml before they reach a runner: %d rules, offline, one binary.", len(ids)),
		Path:        "/",
		Sample:      homeSample(reports[0].Output, homeFindings),
		Covered:     covered,
	}, "home.html"); err != nil {
		return err
	}

	if err := write(Page{
		Title:       "Example reports · glsec",
		Description: "What glsec's text, table, GitLab Code Quality, JUnit, SARIF, GitLab SAST, template and JSON output look like, where GitLab shows each one, and the CycloneDX inventory of a pipeline.",
		Path:        "/reports/",
		Reports:     reports,
		Input:       strings.Split(input, "\n"),
		Inventory:   inventory,
	}, "reports.html"); err != nil {
		return err
	}

	if err := write(Page{
		Title:       "OWASP Top 10 CI/CD Security Risks in GitLab · glsec",
		Description: fmt.Sprintf("How glsec's %d rules map to the OWASP Top 10 CI/CD Security Risks for GitLab pipelines, and which risks a pipeline file can't show.", len(ids)),
		Path:        "/owasp/",
		Risks:       risks,
		Covered:     covered,
		Outside:     outside,
	}, "owasp.html"); err != nil {
		return err
	}

	if err := write(Page{
		Title:       "Performance · glsec",
		Description: "How long glsec takes to scan the same large pipeline, release by release and commit by commit.",
		Path:        "/performance/",
		Perf:        perf,
	}, "performance.html"); err != nil {
		return err
	}

	overview, err := conv.render(src, "docs/rules.md", true)
	if err != nil {
		return err
	}
	if err := write(Page{
		Title:       "Rules · glsec",
		Description: fmt.Sprintf("All %d glsec rules for GitLab CI/CD pipelines, grouped by the OWASP Top 10 CI/CD Security Risks.", len(ids)),
		Path:        "/rules/",
		Body:        overview,
	}, "overview.html"); err != nil {
		return err
	}

	for _, id := range ids {
		file := "docs/rules/" + id + ".md"
		raw, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(file)))
		if err != nil {
			return err
		}
		first, rest, _ := strings.Cut(string(raw), "\n")
		m := ruleTitleRe.FindStringSubmatch(strings.TrimSpace(first))
		if m == nil || m[1] != id {
			return fmt.Errorf("%s: first line %q is not \"# %s — <title>\"", file, first, id)
		}
		body, err := conv.convert(file, []byte(rest), false)
		if err != nil {
			return err
		}
		titleHTML, err := conv.convert(file, []byte(m[2]), false)
		if err != nil {
			return err
		}
		inline := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(string(titleHTML)), "<p>"), "</p>")
		r := &Rule{ID: id, Title: strings.ReplaceAll(m[2], "`", ""), TitleHTML: template.HTML(inline), Body: body} //nolint:gosec // goldmark output with raw HTML disabled
		if err := write(Page{
			Title:       id + ": " + r.Title + " · glsec",
			Description: id + " " + r.Title + ": what glsec reports, why it matters, and the safe alternative.",
			Path:        "/rules/" + id + "/",
			Rule:        r,
		}, "rule.html"); err != nil {
			return err
		}
	}

	if err := write(Page{Title: "Not found · glsec", Path: "/404.html"}, "404.html"); err != nil {
		return err
	}
	if err := copyStatic(out); err != nil {
		return err
	}
	if err := writeSitemap(out, urls); err != nil {
		return err
	}
	return checkLinks(out)
}

var hrefRe = regexp.MustCompile(`(?:href|src)="(/[^"#]*)`)

// checkLinks fails the build when a page links to a site path that has no file.
func checkLinks(out string) error {
	var broken []string
	err := filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range hrefRe.FindAllStringSubmatch(string(data), -1) {
			target := filepath.Join(out, filepath.FromSlash(m[1]))
			if strings.HasSuffix(m[1], "/") {
				target = filepath.Join(target, "index.html")
			}
			if _, err := os.Stat(target); err != nil {
				rel, _ := filepath.Rel(out, p)
				broken = append(broken, rel+" -> "+m[1])
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(broken) > 0 {
		return fmt.Errorf("broken links:\n  %s", strings.Join(broken, "\n  "))
	}
	return nil
}

// ruleIDs lists the rules that have a doc, sorted.
func ruleIDs(src string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(src, "docs", "rules"))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if m := ruleFileRe.FindStringSubmatch("docs/rules/" + e.Name()); m != nil {
			ids = append(ids, m[1])
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%s: no docs/rules/GLxxx.md", src)
	}
	sort.Strings(ids)
	return ids, nil
}

type converter struct {
	version string
}

func newMarkdown(fix *linkFixer) goldmark.Markdown {
	// Raw HTML stays off (goldmark's default), so comments such as
	// "<!-- schema: skip -->" in the docs are dropped and nothing in a doc can
	// add markup to the page.
	return goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
			parser.WithASTTransformers(util.Prioritized(fix, 100)),
		),
	)
}

func (c converter) render(src, file string, dropTitle bool) (template.HTML, error) {
	raw, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(file)))
	if err != nil {
		return "", err
	}
	return c.convert(file, raw, dropTitle)
}

// convert renders one Markdown file of the glsec repository. dropTitle removes
// a leading level-1 heading, which the template shows instead.
func (c converter) convert(file string, raw []byte, dropTitle bool) (template.HTML, error) {
	fix := &linkFixer{file: file, version: c.version}
	var buf bytes.Buffer
	md := newMarkdown(fix)
	doc := md.Parser().Parse(text.NewReader(raw))
	if dropTitle {
		if h, ok := doc.FirstChild().(*ast.Heading); ok && h.Level == 1 {
			doc.RemoveChild(doc, h)
		}
	}
	if err := md.Renderer().Render(&buf, raw, doc); err != nil {
		return "", err
	}
	if fix.err != nil {
		return "", fix.err
	}
	return template.HTML(buf.String()), nil //nolint:gosec // goldmark output with raw HTML disabled
}

// linkFixer points relative links in a doc at the site: another rule doc
// becomes its page, docs/rules.md the overview, and anything else the file on
// GitHub at the release tag.
type linkFixer struct {
	file    string
	version string
	err     error
}

func (f *linkFixer) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if l, ok := n.(*ast.Link); ok && entering {
			dest, err := f.fix(string(l.Destination))
			if err != nil && f.err == nil {
				f.err = err
			}
			l.Destination = []byte(dest)
		}
		return ast.WalkContinue, nil
	})
}

func (f *linkFixer) fix(dest string) (string, error) {
	if dest == "" || strings.HasPrefix(dest, "#") || strings.Contains(dest, "://") || strings.HasPrefix(dest, "mailto:") {
		return dest, nil
	}
	target, frag, _ := strings.Cut(dest, "#")
	if frag != "" {
		frag = "#" + frag
	}
	resolved := path.Clean(path.Join(path.Dir(f.file), target))
	if strings.HasPrefix(resolved, "../") || resolved == ".." {
		return "", fmt.Errorf("%s: link %q leaves the repository", f.file, dest)
	}
	if m := ruleFileRe.FindStringSubmatch(resolved); m != nil {
		return "/rules/" + m[1] + "/" + frag, nil
	}
	if resolved == "docs/rules.md" {
		return "/rules/" + frag, nil
	}
	return repoURL + "/blob/v" + f.version + "/" + resolved + frag, nil
}

func copyStatic(out string) error {
	return fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(out, filepath.FromSlash(strings.TrimPrefix(p, "static/")))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
}

func writeSitemap(out string, urls []string) error {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, u := range urls {
		fmt.Fprintf(&b, "  <url><loc>%s</loc></url>\n", template.HTMLEscapeString(u))
	}
	b.WriteString("</urlset>\n")
	if err := os.WriteFile(filepath.Join(out, "sitemap.xml"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	robots := "User-agent: *\nAllow: /\nSitemap: " + siteURL + "/sitemap.xml\n"
	return os.WriteFile(filepath.Join(out, "robots.txt"), []byte(robots), 0o644)
}
