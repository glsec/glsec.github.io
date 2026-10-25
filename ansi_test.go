// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"html/template"
	"testing"
)

func TestAnsiLines(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want []template.HTML
	}{
		"plain text is escaped": {
			in:   `<b> & "x"`,
			want: []template.HTML{`&lt;b&gt; &amp; &#34;x&#34;`},
		},
		"glsec's severity and rule": {
			in:   "\x1b[31merror\x1b[0m[\x1b[1mGL001\x1b[0m]: msg",
			want: []template.HTML{`<span class="ansi-red">error</span>[<span class="ansi-bold">GL001</span>]: msg`},
		},
		"warn is yellow": {
			in:   "\x1b[33mwarn\x1b[0m",
			want: []template.HTML{`<span class="ansi-yellow">warn</span>`},
		},
		"combined codes": {
			in:   "\x1b[1;31mx\x1b[22my\x1b[39mz",
			want: []template.HTML{`<span class="ansi-bold ansi-red">x</span><span class="ansi-red">y</span>z`},
		},
		"a style carries over a line break": {
			in:   "\x1b[1mone\ntwo\x1b[0m three",
			want: []template.HTML{`<span class="ansi-bold">one</span>`, `<span class="ansi-bold">two</span> three`},
		},
		"unknown codes and other escapes are dropped": {
			in:   "\x1b[4munder\x1b[0m \x1b[2Kclear \x1b]0;title",
			want: []template.HTML{`under clear 0;title`},
		},
		"no empty spans": {
			in:   "\x1b[1m\x1b[0mx",
			want: []template.HTML{`x`},
		},
	} {
		got := ansiLines(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%s: %d lines, want %d: %q", name, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: line %d = %q, want %q", name, i, got[i], c.want[i])
			}
		}
	}
}
