// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"html"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	seoTitleRe       = regexp.MustCompile(`<title>([^<]*)</title>`)
	seoDescriptionRe = regexp.MustCompile(`<meta name="description" content="([^"]*)">`)
	seoCanonicalRe   = regexp.MustCompile(`<link rel="canonical" href="([^"]*)">`)
	seoOGURLRe       = regexp.MustCompile(`<meta property="og:url" content="([^"]*)">`)
	seoLocRe         = regexp.MustCompile(`<loc>([^<]*)</loc>`)
)

// Every page a search engine sees has a title, a description, its own URL as
// canonical and og:url, one h1, and an entry in the sitemap; the sitemap lists
// no URL without a page (#38).
func TestBuild_SEO(t *testing.T) {
	out := buildFixture(t)
	sitemap := map[string]bool{}
	for _, m := range seoLocRe.FindAllStringSubmatch(read(t, filepath.Join(out, "sitemap.xml")), -1) {
		sitemap[m[1]] = true
	}

	titles, descriptions := map[string]string{}, map[string]string{}
	pages := 0
	err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.Name() != "index.html" {
			return err
		}
		pages++
		rel, _ := filepath.Rel(out, filepath.Dir(path))
		url := siteURL + "/"
		if rel != "." {
			url += filepath.ToSlash(rel) + "/"
		}
		page := read(t, path)
		head, _, _ := strings.Cut(page, "</head>")

		one := func(name string, re *regexp.Regexp) string {
			ms := re.FindAllStringSubmatch(head, -1)
			if len(ms) != 1 || strings.TrimSpace(ms[0][1]) == "" {
				t.Errorf("%s: %d %s, want one that isn't empty", url, len(ms), name)
				return ""
			}
			return html.UnescapeString(ms[0][1])
		}
		title, description := one("title", seoTitleRe), one("description", seoDescriptionRe)
		for _, got := range []string{one("canonical", seoCanonicalRe), one("og:url", seoOGURLRe)} {
			if got != "" && got != url {
				t.Errorf("%s: canonical or og:url is %s", url, got)
			}
		}
		if n := strings.Count(page, "<h1"); n != 1 {
			t.Errorf("%s: %d h1, want 1", url, n)
		}
		if !sitemap[url] {
			t.Errorf("%s is not in the sitemap", url)
		}
		delete(sitemap, url)

		if other, ok := titles[title]; ok && title != "" {
			t.Errorf("%s and %s share the title %q", url, other, title)
		}
		titles[title] = url
		if other, ok := descriptions[description]; ok && description != "" {
			t.Errorf("%s and %s share the description %q", url, other, description)
		}
		descriptions[description] = url
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if page := read(t, filepath.Join(out, "404.html")); !seoDescriptionRe.MatchString(page) {
		t.Error("404.html has no description")
	}
	if pages < 8 {
		t.Errorf("checked %d pages", pages)
	}
	for url := range sitemap {
		t.Errorf("the sitemap lists %s, which has no page", url)
	}
}
