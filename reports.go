// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// Report is one output format, shown on /reports/ with glsec's real output
// for sample/.gitlab-ci.yml.
type Report struct {
	Format string // the --format value, and the file name in the reports directory
	Name   string
	Use    string // where the output goes
	Where  string // where it shows up, with the GitLab tiers
	Wiring string // a job that publishes it, if GitLab reads it as a report
	Open   bool   // show the output expanded
	Output string // as glsec printed it, with terminal colours for text
	HTML   template.HTML
	Shot   *Screenshot
}

// Screenshot shows where a report appears in GitLab. It is taken by hand from
// a merge request kept open for this, so it doesn't follow the release.
type Screenshot struct {
	Src, Alt, Caption, Link string
}

// reportFormats are glsec's output formats in the order the page shows them.
// The tier statements follow GitLab's documentation for each report type.
var reportFormats = []Report{
	{Format: "text", Name: "Text", Open: true,
		Use:   "The default. Every finding with the rule, file, line, job and the source line, for the job log or a terminal.",
		Where: "The job log."},
	{Format: "table", Name: "Table", Open: true,
		Use:   "One aligned row per finding, for a quick overview of many findings.",
		Where: "The job log."},
	{Format: "codeclimate", Name: "GitLab Code Quality",
		Use:   "The Code Climate JSON that GitLab's Code Quality report reads.",
		Where: "The merge request's Code Quality report on all tiers. With Premium also a Code Quality tab in the pipeline, with Ultimate inline in the merge request diff.",
		Shot: &Screenshot{
			Src:     "/screenshots/code-quality-mr.png",
			Alt:     "GitLab merge request Code Quality report: Code Quality scans found 4 new findings, two Critical (mutable image tag python:latest, curl piped to sh) and two Major (pipe without pipefail, deploy job without a pipeline-source guard), each with its line in bad-pipeline.yml",
			Caption: "The Code Quality report of a merge request on GitLab.com (Free tier) that adds a job with four findings.",
			Link:    "https://gitlab.com/glsec-io/examples/component-code-quality/-/merge_requests/7",
		},
		Wiring: `glsec:
  image:
    name: ghcr.io/glsec/glsec:{{VERSION}}
    entrypoint: [""]
  script:
    - glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json || true
  artifacts:
    when: always
    expire_in: 30 days
    reports:
      codequality: gl-code-quality.json`},
	{Format: "junit", Name: "JUnit", Open: true,
		Use:   "Each finding as a failed test case.",
		Where: "The pipeline's Tests tab and the test summary in the merge request, on all tiers.",
		Wiring: `glsec:
  image:
    name: ghcr.io/glsec/glsec:{{VERSION}}
    entrypoint: [""]
  script:
    - glsec --format junit .gitlab-ci.yml > glsec-junit.xml || true
  artifacts:
    when: always
    expire_in: 30 days
    reports:
      junit: glsec-junit.xml`,
		Shot: &Screenshot{
			Src:     "/screenshots/junit-tests.png",
			Alt:     "GitLab pipeline Tests tab for the glsec-junit job: 5 tests, 5 failures; each failed test case is a finding, such as GL001 in job build at bad-pipeline.yml:5, GL002 and GL025 in job deploy at line 12, GL053 at line 1 and GL080 in job deploy at line 9",
			Caption: "The Tests tab of a pipeline on GitLab.com (Free tier): every glsec finding is a failed test case.",
			Link:    "https://gitlab.com/glsec-io/examples/docker/-/pipelines/2986914746/test_report?job_name=glsec-junit",
		}},
	{Format: "sarif", Name: "SARIF",
		Use:   "SARIF 2.1.0 with CWE, OWASP and ASVS mappings for each rule.",
		Where: "GitHub Code Scanning and other tools that read SARIF."},
	{Format: "json", Name: "JSON",
		Use:   "One object per finding with its OWASP and ASVS mappings, for scripts and dashboards.",
		Where: "Wherever you send it."},
}

// loadReports reads the scanned file, <dir>/input.yml, and <dir>/<format>.txt
// for every format.
func loadReports(dir, version string) (string, []Report, error) {
	input, err := os.ReadFile(filepath.Join(dir, "input.yml")) //nolint:gosec // dir comes from the build script
	if err != nil {
		return "", nil, err
	}
	reports := make([]Report, 0, len(reportFormats))
	for _, r := range reportFormats {
		data, err := os.ReadFile(filepath.Join(dir, r.Format+".txt")) //nolint:gosec // dir comes from the build script
		if err != nil {
			return "", nil, err
		}
		out := strings.TrimRight(string(data), "\n")
		if out == "" {
			return "", nil, fmt.Errorf("%s: glsec printed nothing for --format %s", dir, r.Format)
		}
		r.Output = out
		r.HTML = ansiHTML(out)
		r.Wiring = strings.ReplaceAll(r.Wiring, "{{VERSION}}", version)
		reports = append(reports, r)
	}
	return strings.TrimRight(string(input), "\n"), reports, nil
}
