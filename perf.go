// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// perfStart is the first release the performance page shows. The benchmark
// history goes back to v0.1.0, but the two 0.x prototypes predate most rules.
const perfStart = "1.0.0"

// perfInputVersion selects the input the page charts; a new input on the
// benchmarks branch starts a new series (glsec/glsec#875).
const perfInputVersion = 1

// benchRecord is one line of data/benchmarks.jsonl on glsec's benchmarks
// branch. The branch README documents every field.
type benchRecord struct {
	Kind         string `json:"kind"`
	Commit       string `json:"commit"`
	Date         string `json:"date"`
	Version      string `json:"version"`
	Rules        *int   `json:"rules"`
	InputVersion int    `json:"input_version"`
	Ref          string `json:"ref"` // schema 2: the release the ratio compares against
	CLI          struct {
		MedianMS float64  `json:"median_ms"`
		Ratio    *float64 `json:"ratio"` // schema 2: median_ms / the median of ref, same job
	} `json:"cli"`
	GoBench map[string]struct {
		Allocs float64 `json:"allocs_per_op"`
	} `json:"go_bench"`
	CPU        string `json:"cpu"`
	MeasuredAt string `json:"measured_at"`
}

// PerfPoint is one commit on the performance chart.
type PerfPoint struct {
	Commit  string
	Date    string // YYYY-MM-DD
	Release string // tag, empty for a main commit
	MS      float64
	Rules   int // 0 when the version has no glsec list
	CPU     string
	Allocs  float64 // BenchmarkRules allocs/op, 0 without Go benchmarks
	Ratio   float64 // time relative to Ref, measured in the same job; 0 without
	Ref     string
}

// RatioText is the ratio as the page writes it, "0.51 × v1.24.1".
func (p PerfPoint) RatioText() string {
	if p.Ratio == 0 {
		return ""
	}
	return strconv.FormatFloat(p.Ratio, 'f', 2, 64) + " × " + p.Ref
}

// Short is the abbreviated commit.
func (p PerfPoint) Short() string { return p.Commit[:min(7, len(p.Commit))] }

// Label names the point: its release tag or its commit.
func (p PerfPoint) Label() string {
	if p.Release != "" {
		return p.Release
	}
	return p.Short()
}

// URL is the commit on GitHub.
func (p PerfPoint) URL() string { return repoURL + "/commit/" + p.Commit }

// Perf is everything the performance page shows.
type Perf struct {
	Points []PerfPoint   // every release and commit, for the table
	Time   template.HTML // the releases' scan time, all from one backfill run
	Ratio  template.HTML // commits since the latest release relative to it, empty without any
	Allocs template.HTML // allocations of the latest commits, empty with fewer than two
	Latest PerfPoint     // the latest release
	Commit *PerfPoint    // the latest commit with a ratio, nil without
	First  PerfPoint     // the first release with a rule count
	Start  string
}

// maxAllocPoints caps the allocation chart; older commits stay in the table.
const maxAllocPoints = 60

type tagRef struct {
	Name string `json:"name"`
	SHA  string `json:"sha"`
}

var releaseTagRe = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// loadPerf reads the benchmark history and the release tags, keeps one point
// per commit (the latest measurement) from perfStart on, and draws the charts.
func loadPerf(benchPath, tagsPath string) (*Perf, error) {
	tags, err := loadTags(tagsPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(benchPath) //nolint:gosec // the build script's own download
	if err != nil {
		return nil, err
	}
	latest := map[string]benchRecord{}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r benchRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", benchPath, n+1, err)
		}
		if r.InputVersion != perfInputVersion || r.Commit == "" || len(r.Date) < 10 {
			continue
		}
		if old, ok := latest[r.Commit]; !ok || r.MeasuredAt > old.MeasuredAt {
			latest[r.Commit] = r
		}
	}

	start := versionKey("v" + perfStart)
	var points []PerfPoint
	for _, r := range latest {
		p := PerfPoint{Commit: r.Commit, Date: r.Date[:10], Release: tags[r.Commit], MS: r.CLI.MedianMS, CPU: r.CPU}
		if r.Rules != nil {
			p.Rules = *r.Rules
		}
		if b, ok := r.GoBench["BenchmarkRules"]; ok {
			p.Allocs = b.Allocs
		}
		if r.CLI.Ratio != nil && *r.CLI.Ratio > 0 && releaseTagRe.MatchString(r.Ref) {
			p.Ratio, p.Ref = *r.CLI.Ratio, r.Ref
		}
		if p.Release != "" && versionKey(p.Release) < start {
			continue
		}
		if p.Release == "" && r.Kind == "release" {
			continue // a release whose tag is gone
		}
		points = append(points, p)
	}
	if len(points) == 0 {
		return nil, fmt.Errorf("%s: no measurements from v%s on", benchPath, perfStart)
	}
	// Releases by version, main commits by date after the release before them.
	sort.SliceStable(points, func(i, j int) bool {
		a, b := points[i], points[j]
		if a.Date != b.Date {
			return a.Date < b.Date
		}
		if (a.Release != "") != (b.Release != "") {
			return a.Release != ""
		}
		return versionKey(a.Release) < versionKey(b.Release)
	})
	if points[0].Release == "" {
		return nil, fmt.Errorf("%s: the history must start with a release", benchPath)
	}
	p := &Perf{Points: points, Start: perfStart}
	var releases, sinceRelease, allocs []PerfPoint
	for _, pt := range points {
		switch {
		case pt.Release != "":
			releases = append(releases, pt)
			sinceRelease = nil
		case pt.Ratio > 0:
			sinceRelease = append(sinceRelease, pt)
		}
		if pt.Release == "" && pt.Allocs > 0 {
			allocs = append(allocs, pt)
		}
		if p.First.Rules == 0 && pt.Rules > 0 {
			p.First = pt
		}
	}
	p.Latest = releases[len(releases)-1]
	if n := len(sinceRelease); n > 0 {
		p.Commit = &sinceRelease[n-1]
	}
	p.Time = timeChart(releases)
	p.Ratio = ratioChart(sinceRelease)
	p.Allocs = allocChart(allocs[max(0, len(allocs)-maxAllocPoints):])
	return p, nil
}

// loadTags maps commit SHAs to release tags (vX.Y.Z only).
func loadTags(path string) (map[string]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the build script's own download
	if err != nil {
		return nil, err
	}
	var refs []tagRef
	if err := json.Unmarshal(data, &refs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	tags := map[string]string{}
	for _, r := range refs {
		if releaseTagRe.MatchString(r.Name) && (tags[r.SHA] == "" || versionKey(r.Name) > versionKey(tags[r.SHA])) {
			tags[r.SHA] = r.Name
		}
	}
	return tags, nil
}

// versionKey orders release tags; anything else sorts first.
func versionKey(tag string) int {
	m := releaseTagRe.FindStringSubmatch(tag)
	if m == nil {
		return -1
	}
	key := 0
	for _, part := range m[1:] {
		n, _ := strconv.Atoi(part)
		key = key*10000 + n
	}
	return key
}

// Chart geometry, in viewBox units. The SVG scales to the page width.
const (
	chartW, chartH = 800.0, 300.0
	padL, padR     = 64.0, 16.0
	padT, padB     = 16.0, 56.0
	plotW, plotH   = chartW - padL - padR, chartH - padT - padB
	dotRadius      = 4.5
	hitRadius      = 9.0 // the link target around a dot
	maxYTicks      = 5
	maxTagLabels   = 8 // release names under the axis; the rest only as markers
)

func timeChart(points []PerfPoint) template.HTML {
	return chart(points, "time", "Scan time", 1, 0, 0,
		func(p PerfPoint) float64 { return p.MS },
		func(p PerfPoint) string { return thousands(p.MS) + " ms" })
}

// ratioChart shows the commits since the latest release against it, on a
// scale that reaches at least ratioTop so the charts read alike over time.
func ratioChart(points []PerfPoint) template.HTML {
	if len(points) == 0 {
		return ""
	}
	return chart(points, "ratio", "Time relative to the release", 1, ratioTop, 1,
		func(p PerfPoint) float64 { return p.Ratio },
		func(p PerfPoint) string { return p.RatioText() + " (" + thousands(p.MS) + " ms)" })
}

// ratioTop is the least top of the ratio chart's scale.
const ratioTop = 1.5

// allocChart is empty until two commits have Go benchmark results.
func allocChart(points []PerfPoint) template.HTML {
	if len(points) < 2 {
		return ""
	}
	return chart(points, "allocs", "Allocations", 1e6, 0, 0,
		func(p PerfPoint) float64 { return p.Allocs },
		func(p PerfPoint) string { return thousands(p.Allocs) + " allocations" })
}

// chart draws points as an SVG line chart. x is the order of the
// measurements, so releases a day apart don't pile up; y starts at zero and
// reaches at least minTop. A non-zero refLine draws a reference at that value.
// Every dot links to its commit with a native tooltip, and release markers are
// named where there is room.
func chart(points []PerfPoint, id, title string, unit, minTop, refLine float64, value func(PerfPoint) float64, describe func(PerfPoint) string) template.HTML {
	maxV := minTop
	for _, p := range points {
		maxV = math.Max(maxV, value(p)/unit)
	}
	step := niceStep(maxV / maxYTicks)
	top := math.Max(math.Ceil(maxV/step)*step, step)
	x := func(i int) float64 {
		if len(points) == 1 {
			return padL + plotW/2
		}
		return padL + plotW*float64(i)/float64(len(points)-1)
	}
	y := func(p PerfPoint) float64 { return padT + plotH*(1-value(p)/unit/top) }

	var b strings.Builder
	// A group, not an img: an img hides the dots' links from assistive technology (#37).
	fmt.Fprintf(&b, `<svg class="perf-chart" viewBox="0 0 %g %g" role="group" aria-labelledby="perf-%s">`, chartW, chartH, id)
	fmt.Fprintf(&b, `<title id="perf-%s">%s by release and commit; the table below lists every value</title>`, id, title)
	for v := 0.0; v <= top+step/2; v += step {
		yy := padT + plotH*(1-v/top)
		fmt.Fprintf(&b, `<line class="perf-grid" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/>`, padL, chartW-padR, yy, yy)
		fmt.Fprintf(&b, `<text class="perf-axis" x="%g" y="%.1f" text-anchor="end" dy="0.32em">%s</text>`, padL-8, yy, thousands(v))
	}
	if refLine > 0 {
		yy := padT + plotH*(1-refLine/top)
		fmt.Fprintf(&b, `<line class="perf-ref" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/>`, padL, chartW-padR, yy, yy)
	}

	var releases []int
	for i, p := range points {
		if p.Release != "" {
			releases = append(releases, i)
		}
	}
	// A chart of commits only names its first and last date instead.
	if len(releases) == 0 {
		ends := []int{0}
		if len(points) > 1 {
			ends = append(ends, len(points)-1)
		}
		for _, i := range ends {
			xx, yy := x(i), padT+plotH+14
			fmt.Fprintf(&b, `<text class="perf-axis" x="%.1f" y="%g" text-anchor="end" transform="rotate(-40 %.1f %g)">%s</text>`, xx, yy, xx, yy, points[i].Date)
		}
	}
	every := max(1, int(math.Ceil(float64(len(releases))/maxTagLabels)))
	for n, i := range releases {
		xx, yy := x(i), padT+plotH+14
		fmt.Fprintf(&b, `<line class="perf-marker" x1="%.1f" x2="%.1f" y1="%g" y2="%g"/>`, xx, xx, padT, padT+plotH)
		if n%every == 0 || n == len(releases)-1 {
			fmt.Fprintf(&b, `<text class="perf-axis" x="%.1f" y="%g" text-anchor="end" transform="rotate(-40 %.1f %g)">%s</text>`, xx, yy, xx, yy, points[i].Release)
		}
	}

	var path strings.Builder
	for i, p := range points {
		cmd := "L"
		if i == 0 {
			cmd = "M"
		}
		fmt.Fprintf(&path, "%s%.1f %.1f", cmd, x(i), y(p))
	}
	fmt.Fprintf(&b, `<path class="perf-line" d="%s"/>`, path.String())

	for i, p := range points {
		class := "perf-main"
		if p.Release != "" {
			class = "perf-release"
		}
		tip := fmt.Sprintf("%s · %s · %s", p.Label(), p.Date, describe(p))
		if p.Rules > 0 {
			tip += fmt.Sprintf(" · %d rules", p.Rules)
		}
		if p.CPU != "" {
			tip += " · " + p.CPU
		}
		fmt.Fprintf(&b, `<a href="%s"><title>%s</title><circle class="perf-hit" cx="%.1f" cy="%.1f" r="%g"/><circle class="%s" cx="%.1f" cy="%.1f" r="%g"/></a>`,
			p.URL(), template.HTMLEscapeString(tip), x(i), y(p), hitRadius, class, x(i), y(p), dotRadius)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // numbers, fixed markup and escaped text
}

// niceStep rounds a raw tick distance up to 1, 2 or 5 times a power of ten.
func niceStep(raw float64) float64 {
	if raw <= 0 {
		return 1
	}
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 2, 5, 10} {
		if raw <= m*mag {
			return m * mag
		}
	}
	return 10 * mag
}

// thousands formats a number with comma separators: whole numbers from 100
// on, one decimal below.
func thousands(v float64) string {
	s := strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
	if v >= 100 {
		s = strconv.FormatFloat(math.Round(v), 'f', 0, 64)
	}
	intPart, frac, _ := strings.Cut(s, ".")
	var out []byte
	for i, c := range []byte(intPart) {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if frac != "" {
		return string(out) + "." + frac
	}
	return string(out)
}
