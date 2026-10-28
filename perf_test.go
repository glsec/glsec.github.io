// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPerf(t *testing.T) {
	p, err := loadPerf("testdata/bench.jsonl", "testdata/tags.json")
	if err != nil {
		t.Fatal(err)
	}
	// v0.1.0 is before perfStart; the input_version 2 record is another
	// series; commit 5 has two records and keeps the later one.
	var got []string
	for _, pt := range p.Points {
		got = append(got, pt.Label()+"="+thousands(pt.MS))
	}
	if want := "v1.0.0=397 v1.3.0=492 v1.24.1=1,799 0000000=946"; strings.Join(got, " ") != want {
		t.Errorf("points %q, want %q", strings.Join(got, " "), want)
	}
	if p.Latest.CPU != "CPU A" || p.Latest.Release != "" {
		t.Errorf("latest = %+v, want the backfill measurement of commit 5", p.Latest)
	}
	if p.First.Label() != "v1.3.0" || p.First.Rules != 64 {
		t.Errorf("first with rules = %s/%d, want v1.3.0/64", p.First.Label(), p.First.Rules)
	}
	svg := string(p.Time)
	for _, want := range []string{
		`href="https://github.com/glsec/glsec/commit/0000000000000000000000000000000000000004"`,
		`<title>v1.24.1 · 2026-10-26 · 1,799 ms · 89 rules · CPU A</title>`,
		`class="perf-release"`, `class="perf-main"`, `class="perf-marker"`, `>v1.24.1</text>`,
	} {
		if !strings.Contains(svg, want) {
			t.Errorf("time chart lacks %s", want)
		}
	}
	// One commit with Go benchmarks: no allocation chart yet.
	if p.Allocs != "" {
		t.Error("allocation chart drawn for a single commit")
	}
}

func TestAllocChart(t *testing.T) {
	points := []PerfPoint{
		{Commit: "a1", Date: "2026-10-28", Release: "v1.25.0", MS: 900, Allocs: 3_304_131},
		{Commit: "b2", Date: "2026-10-29", MS: 880, Allocs: 3_100_000},
	}
	svg := string(allocChart(points))
	if !strings.Contains(svg, `3,304,131 allocations`) || !strings.Contains(svg, `>4</text>`) {
		t.Errorf("allocation chart misses a value or tick:\n%s", svg)
	}
}

func TestLoadPerf_Rejects(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tags := write("tags.json", `[{"name":"v1.0.0","sha":"aaa"}]`)
	for name, tc := range map[string]struct{ bench, tags string }{
		"broken record":    {write("broken.jsonl", "{not json\n"), tags},
		"nothing in range": {write("empty.jsonl", "\n"), tags},
		"starts with main": {write("main.jsonl", `{"kind":"main","commit":"bbb","date":"2026-10-28T00:00:00Z","input_version":1,"cli":{"median_ms":1}}`+"\n"), tags},
		"broken tags":      {write("ok.jsonl", `{"kind":"release","commit":"aaa","date":"2026-10-28T00:00:00Z","input_version":1,"cli":{"median_ms":1}}`+"\n"), write("bad.json", "{")},
		"missing file":     {filepath.Join(dir, "absent.jsonl"), tags},
	} {
		if _, err := loadPerf(tc.bench, tc.tags); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestVersionKey(t *testing.T) {
	if versionKey("v1.9.0") >= versionKey("v1.10.0") || versionKey("v0.2.0") >= versionKey("v1.0.0") {
		t.Error("versions out of order")
	}
	if versionKey("main") != -1 {
		t.Error("non-release tag must sort first")
	}
}

func TestNiceStepAndThousands(t *testing.T) {
	for raw, want := range map[float64]float64{0: 1, 360: 500, 0.7: 1, 0.66: 1, 12: 20, 0.21: 0.5} {
		if got := niceStep(raw); got != want {
			t.Errorf("niceStep(%g) = %g, want %g", raw, got, want)
		}
	}
	for v, want := range map[float64]string{1799.4: "1,799", 3304131: "3,304,131", 3.5: "3.5", 0: "0", 652.6: "653"} {
		if got := thousands(v); got != want {
			t.Errorf("thousands(%g) = %q, want %q", v, got, want)
		}
	}
}

func TestBuild_PerformancePage(t *testing.T) {
	page := read(t, filepath.Join(buildFixture(t), "performance", "index.html"))
	for _, want := range []string{
		`<svg class="perf-chart"`, `Every release since v1.0.0`, `from 64 rules in v1.3.0 to 89 now`,
		`aria-current="page">Performance`, `and get their own chart once there are two`,
		`<td><a href="https://github.com/glsec/glsec/commit/0000000000000000000000000000000000000002">v1.0.0</a></td>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("performance page lacks %s", want)
		}
	}
}
