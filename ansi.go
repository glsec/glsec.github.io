// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"html"
	"html/template"
	"regexp"
	"strings"
)

// sgrRe matches an SGR escape sequence such as "\x1b[1m" or "\x1b[0;31m".
var sgrRe = regexp.MustCompile(`\x1b\[([0-9;]*)m`)

// emptySpanRe matches a span left empty by two codes in a row.
var emptySpanRe = regexp.MustCompile(`<span class="[a-z -]*"></span>`)

// otherEscRe matches any other escape sequence, which is dropped.
var otherEscRe = regexp.MustCompile(`\x1b(\[[0-9;?]*[A-Za-z]|[^\[])`)

// ansiStyle is the formatting glsec's terminal output uses: bold, and red for
// errors or yellow for warnings.
type ansiStyle struct {
	bold  bool
	color string // "red", "yellow" or ""
}

func (s ansiStyle) classes() string {
	var c []string
	if s.bold {
		c = append(c, "ansi-bold")
	}
	if s.color != "" {
		c = append(c, "ansi-"+s.color)
	}
	return strings.Join(c, " ")
}

func (s ansiStyle) apply(params string) ansiStyle {
	if params == "" {
		return ansiStyle{}
	}
	for _, p := range strings.Split(params, ";") {
		switch p {
		case "", "0":
			s = ansiStyle{}
		case "1":
			s.bold = true
		case "22":
			s.bold = false
		case "31":
			s.color = "red"
		case "33":
			s.color = "yellow"
		case "39":
			s.color = ""
		}
	}
	return s
}

// ansiLines turns terminal output into HTML lines: text is escaped, the SGR
// codes glsec uses become spans with ansi-* classes, and every other escape
// sequence is dropped. A style carries over into the next line, as it would
// in a terminal, but every line closes its own spans.
func ansiLines(out string) []template.HTML {
	var lines []template.HTML
	var style ansiStyle
	for _, line := range strings.Split(out, "\n") {
		var b strings.Builder
		open := func() {
			if c := style.classes(); c != "" {
				b.WriteString(`<span class="` + c + `">`)
			}
		}
		closeSpan := func() {
			if style.classes() != "" {
				b.WriteString("</span>")
			}
		}
		open()
		rest := line
		for {
			loc := sgrRe.FindStringSubmatchIndex(rest)
			if loc == nil {
				b.WriteString(html.EscapeString(otherEscRe.ReplaceAllString(rest, "")))
				break
			}
			b.WriteString(html.EscapeString(otherEscRe.ReplaceAllString(rest[:loc[0]], "")))
			closeSpan()
			style = style.apply(rest[loc[2]:loc[3]])
			open()
			rest = rest[loc[1]:]
		}
		closeSpan()
		lines = append(lines, template.HTML(emptySpanRe.ReplaceAllString(b.String(), ""))) //nolint:gosec // text is escaped above; only fixed span tags are added
	}
	return lines
}

// ansiHTML is ansiLines joined back into one block.
func ansiHTML(out string) template.HTML {
	lines := ansiLines(out)
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = string(l)
	}
	return template.HTML(strings.Join(parts, "\n")) //nolint:gosec // built from ansiLines
}

// homeFindings is how many findings the home page terminal shows.
const homeFindings = 3

// findingStartRe matches the first line of a finding in glsec's text output,
// once the colour codes are removed.
var findingStartRe = regexp.MustCompile(`^(error|warn|info)\[`)

// homeSample is the text output cut after max findings, with a last line that
// says how many more there are and links the full report.
func homeSample(out string, max int) []template.HTML {
	lines := ansiLines(out)
	plain := strings.Split(sgrRe.ReplaceAllString(out, ""), "\n")
	var starts []int
	for i, l := range plain {
		if findingStartRe.MatchString(l) {
			starts = append(starts, i)
		}
	}
	if len(starts) <= max {
		return lines
	}
	kept := lines[:starts[max]]
	for len(kept) > 0 && strings.TrimSpace(string(kept[len(kept)-1])) == "" {
		kept = kept[:len(kept)-1]
	}
	more, noun := len(starts)-max, "findings"
	if more == 1 {
		noun = "finding"
	}
	return append(kept, "", template.HTML(fmt.Sprintf(`<span class="more">… and %d more %s: <a href="/reports/#text">see the full report</a></span>`, more, noun))) //nolint:gosec // fixed markup and a number
}
