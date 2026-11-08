// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// advisoriesFile lists the known attacks behind glsec's rules. Releases before
// it existed build without the attacks page.
const advisoriesFile = "docs/advisories.yml"

// Advisory is one entry of docs/advisories.yml. The file's header comment
// documents the keys; cmd/glsec/advisories_test.go in glsec checks them too.
type Advisory struct {
	ID       string         `yaml:"id"`
	Aliases  []string       `yaml:"aliases"`
	Repo     string         `yaml:"repo"`
	Kind     string         `yaml:"kind"`
	Product  string         `yaml:"product"`
	Fixed    string         `yaml:"fixed"`
	Summary  string         `yaml:"summary"`
	Coverage string         `yaml:"coverage"`
	Rules    []AdvisoryRule `yaml:"rules"`
	Reason   string         `yaml:"reason"`
	Issue    int            `yaml:"issue"`
	Note     string         `yaml:"note"`
	Steps    []AdvisoryStep `yaml:"steps"`
}

// AdvisoryRule is a rule that reports an advisory's configuration shape.
type AdvisoryRule struct {
	Rule     string `yaml:"rule"`
	Severity string `yaml:"severity"`
}

// AdvisoryStep is one step of a campaign: the rules that see it, or why none
// does.
type AdvisoryStep struct {
	Step   string   `yaml:"step"`
	Rules  []string `yaml:"rules"`
	Reason string   `yaml:"reason"`
}

// Attacks is what the attacks page shows, in the page's section order.
type Attacks struct {
	Detected    []Advisory // kind cve, coverage full or partial
	NotDetected []Advisory // kind cve, coverage none
	Campaigns   []Advisory
	Analogues   []Advisory
}

var (
	cveRe  = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// reasonText says in a few words why glsec doesn't see everything.
var reasonText = map[string]string{
	"not-static":  "needs run-time state that a file scan can't see",
	"no-rule-yet": "visible in the pipeline file, not reported yet",
	"by-design":   "deliberately not reported",
}

// URL is the advisory's page: cve.org for a CVE, the GitHub Advisory Database
// or the publishing repository for a GHSA, nothing for a campaign.
func (a Advisory) URL() string {
	switch {
	case cveRe.MatchString(a.ID):
		return "https://www.cve.org/CVERecord?id=" + a.ID
	case ghsaRe.MatchString(a.ID) && a.Repo != "":
		return "https://github.com/" + a.Repo + "/security/advisories/" + a.ID
	case ghsaRe.MatchString(a.ID):
		return "https://github.com/advisories/" + a.ID
	}
	return ""
}

var nonSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

// Anchor is the entry's fragment id: the id in lower case with every run of
// other characters, such as a campaign name's spaces, turned into one dash.
func (a Advisory) Anchor() string {
	return strings.Trim(nonSlugRe.ReplaceAllString(strings.ToLower(a.ID), "-"), "-")
}

// Link is an id with the page it points to.
type Link struct{ ID, URL string }

// AliasLinks are the advisory's other ids, linked where they have a page.
func (a Advisory) AliasLinks() []Link {
	links := make([]Link, 0, len(a.Aliases))
	for _, id := range a.Aliases {
		links = append(links, Link{ID: id, URL: Advisory{ID: id, Repo: a.Repo}.URL()})
	}
	return links
}

// ReasonText is the reason in words, empty for full coverage.
func (a Advisory) ReasonText() string { return reasonText[a.Reason] }

// IssueURL links the tracking issue of a gap.
func (a Advisory) IssueURL() string {
	if a.Issue == 0 {
		return ""
	}
	return fmt.Sprintf("%s/issues/%d", repoURL, a.Issue)
}

// ReasonText is the step's reason in words.
func (s AdvisoryStep) ReasonText() string { return reasonText[s.Reason] }

// loadAdvisories reads docs/advisories.yml from the source tree. A tree
// without the file gives nil. Every rule the file names must be a documented
// rule of the same release, so a renamed or removed rule fails the build
// instead of linking to a missing page.
func loadAdvisories(src string, ids []string) (*Attacks, error) {
	data, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(advisoriesFile))) //nolint:gosec // path comes from the build script
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Advisory
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&list); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", advisoriesFile, err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s: no entries", advisoriesFile)
	}
	known := func(rule string) error {
		if !slices.Contains(ids, rule) {
			return fmt.Errorf("rule %s has no docs/rules/%s.md in this release", rule, rule)
		}
		return nil
	}
	var a Attacks
	seen := map[string]bool{}
	for _, adv := range list {
		if err := checkAdvisory(adv, known); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", advisoriesFile, adv.ID, err)
		}
		if seen[adv.ID] {
			return nil, fmt.Errorf("%s: %s is listed twice", advisoriesFile, adv.ID)
		}
		seen[adv.ID] = true
		switch {
		case adv.Kind == "campaign":
			a.Campaigns = append(a.Campaigns, adv)
		case adv.Kind == "analogue":
			a.Analogues = append(a.Analogues, adv)
		case adv.Coverage == "none":
			a.NotDetected = append(a.NotDetected, adv)
		default:
			a.Detected = append(a.Detected, adv)
		}
	}
	return &a, nil
}

func checkAdvisory(a Advisory, known func(string) error) error {
	switch {
	case a.ID == "":
		return errors.New("no id")
	case a.Kind != "cve" && a.Kind != "analogue" && a.Kind != "campaign":
		return fmt.Errorf("unknown kind %q", a.Kind)
	case a.Kind != "campaign" && !cveRe.MatchString(a.ID) && !ghsaRe.MatchString(a.ID):
		return errors.New("id is neither a CVE nor a GHSA")
	case a.Summary == "" || a.Product == "":
		return errors.New("no summary or product")
	case a.Coverage != "full" && a.Coverage != "partial" && a.Coverage != "none":
		return fmt.Errorf("unknown coverage %q", a.Coverage)
	case a.Coverage != "none" && len(a.Rules) == 0:
		return errors.New("no rules for coverage " + a.Coverage)
	case a.Coverage != "full" && reasonText[a.Reason] == "":
		return fmt.Errorf("unknown or missing reason %q", a.Reason)
	case a.Coverage == "full" && a.Reason != "":
		return errors.New("a reason for full coverage")
	case a.Reason == "no-rule-yet" && a.Issue == 0:
		return errors.New("no-rule-yet without an issue")
	case a.Kind == "campaign" && len(a.Steps) == 0:
		return errors.New("a campaign without steps")
	case a.Kind != "campaign" && len(a.Steps) > 0:
		return errors.New("steps outside a campaign")
	}
	for _, r := range a.Rules {
		if err := known(r.Rule); err != nil {
			return err
		}
	}
	for _, s := range a.Steps {
		if s.Step == "" || (len(s.Rules) == 0) == (s.Reason == "") {
			return fmt.Errorf("step %q needs either rules or a reason", s.Step)
		}
		if s.Reason != "" && reasonText[s.Reason] == "" {
			return fmt.Errorf("step %q: unknown reason %q", s.Step, s.Reason)
		}
		for _, r := range s.Rules {
			if err := known(r); err != nil {
				return err
			}
		}
	}
	return nil
}
