// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

const owaspBase = "https://owasp.org/www-project-top-10-ci-cd-security-risks/"

// Risk is one of the OWASP Top 10 CI/CD Security Risks and the glsec rules
// that report it.
type Risk struct {
	ID      string // "CICD-SEC-1"
	Name    string
	URL     string
	Summary string // what the risk looks like in a GitLab pipeline
	Outside string // why a pipeline file can't show it, for risks no rule covers
	Rules   []ListedRule
}

// ListedRule is one entry of glsec list --format json.
type ListedRule struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	OWASP       []string `json:"owasp"`
	Description string   `json:"description"`
}

// owaspRisks are the ten risks in OWASP's order. The summaries describe them
// in GitLab terms; OWASP's pages have the full text.
var owaspRisks = []Risk{
	{ID: "CICD-SEC-1", Name: "Insufficient Flow Control Mechanisms", URL: owaspBase + "CICD-SEC-01-Insufficient-Flow-Control-Mechanisms",
		Summary: "A change reaches production without the checks meant to stop it: deploy jobs that run on any branch, manual gates that don't block, security scans that are switched off or can't fail."},
	{ID: "CICD-SEC-2", Name: "Inadequate Identity and Access Management", URL: owaspBase + "CICD-SEC-02-Inadequate-Identity-And-Access-Management",
		Outside: "Who can reach the CI/CD system and with which role is set in GitLab's group and project settings, not in .gitlab-ci.yml."},
	{ID: "CICD-SEC-3", Name: "Dependency Chain Abuse", URL: owaspBase + "CICD-SEC-03-Dependency-Chain-Abuse",
		Summary: "The pipeline pulls code that can change under it: mutable image tags, includes from a branch, packages fetched without a lock file or checksum."},
	{ID: "CICD-SEC-4", Name: "Poisoned Pipeline Execution", URL: owaspBase + "CICD-SEC-04-Poisoned-Pipeline-Execution",
		Summary: "Whoever can push a branch or open a merge request gets to run commands in the pipeline, for example through a branch name, commit message or merge request title placed into a script."},
	{ID: "CICD-SEC-5", Name: "Insufficient PBAC (Pipeline-Based Access Controls)", URL: owaspBase + "CICD-SEC-05-Insufficient-PBAC",
		Summary: "Jobs get more access than they need: OIDC tokens with a broad audience or on untrusted pipelines, deploy jobs on any runner, the host's Docker socket."},
	{ID: "CICD-SEC-6", Name: "Insufficient Credential Hygiene", URL: owaspBase + "CICD-SEC-06-Insufficient-Credential-Hygiene",
		Summary: "Secrets end up where they shouldn't: committed in the pipeline file, printed to the job log, packed into artifacts, or forwarded to other hosts and downstream pipelines."},
	{ID: "CICD-SEC-7", Name: "Insecure System Configuration", URL: owaspBase + "CICD-SEC-07-Insecure-System-Configuration",
		Summary: "The pipeline weakens its own environment: privileged Docker, disabled TLS or host key checks, root and sudo, pipes that hide a failing command."},
	{ID: "CICD-SEC-8", Name: "Ungoverned Usage of 3rd Party Services", URL: owaspBase + "CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services",
		Summary: "Third-party code gets into the pipeline without anyone choosing a version, such as a CI/CD component included without a pinned release."},
	{ID: "CICD-SEC-9", Name: "Improper Artifact Integrity Validation", URL: owaspBase + "CICD-SEC-09-Improper-Artifact-Integrity-Validation",
		Summary: "Nobody can check what was built or downloaded: files fetched without a checksum, releases published without a signature."},
	{ID: "CICD-SEC-10", Name: "Insufficient Logging and Visibility", URL: owaspBase + "CICD-SEC-10-Insufficient-Logging-And-Visibility",
		Outside: "Audit logs and their monitoring live in GitLab's instance and group settings and in your log pipeline, not in .gitlab-ci.yml."},
}

// loadRisks reads glsec list --format json and sorts its rules into the ten
// risks, and counts the risks with rules and those outside the pipeline file.
// Every listed rule must have a doc page and a known risk, and every
// documented rule must be listed, so the page can't drift from the release.
func loadRisks(path string, docIDs []string) ([]Risk, int, int, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the build script
	if err != nil {
		return nil, 0, 0, err
	}
	var listed []ListedRule
	if err := json.Unmarshal(data, &listed); err != nil {
		return nil, 0, 0, fmt.Errorf("%s: %w", path, err)
	}
	risks := slices.Clone(owaspRisks)
	index := map[string]int{}
	for i, r := range risks {
		index[r.ID] = i
	}
	seen := map[string]bool{}
	for _, r := range listed {
		if !slices.Contains(docIDs, r.ID) {
			return nil, 0, 0, fmt.Errorf("%s: rule %s has no docs/rules/%s.md", path, r.ID, r.ID)
		}
		if len(r.OWASP) == 0 {
			return nil, 0, 0, fmt.Errorf("%s: rule %s has no OWASP category", path, r.ID)
		}
		seen[r.ID] = true
		for _, cat := range r.OWASP {
			i, ok := index[cat]
			if !ok {
				return nil, 0, 0, fmt.Errorf("%s: rule %s names unknown OWASP category %q", path, r.ID, cat)
			}
			risks[i].Rules = append(risks[i].Rules, r)
		}
	}
	for _, id := range docIDs {
		if !seen[id] {
			return nil, 0, 0, fmt.Errorf("%s: documented rule %s is missing", path, id)
		}
	}
	covered, outside := 0, 0
	for i := range risks {
		slices.SortFunc(risks[i].Rules, func(a, b ListedRule) int { return strings.Compare(a.ID, b.ID) })
		switch {
		case len(risks[i].Rules) > 0 && risks[i].Summary == "":
			return nil, 0, 0, fmt.Errorf("%s has rules but no summary", risks[i].ID)
		case len(risks[i].Rules) > 0:
			covered++
		case risks[i].Outside != "":
			outside++
		}
	}
	return risks, covered, outside, nil
}
