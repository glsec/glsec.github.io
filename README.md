# glsec.github.io

Source of <https://glsec.github.io>, the website and rule reference for [glsec](https://github.com/glsec/glsec).

The rule pages are generated from `docs/rules.md` and `docs/rules/GLxxx.md` in the glsec repository, at the latest release tag, so the site always describes the version people can install. The OWASP page sorts the rules from that release's `glsec list --format json` into the ten OWASP CI/CD risks. The example on the home page and the example reports are the output of that release's binary on [`sample/bad-pipeline.yml`](sample/bad-pipeline.yml), in every format (the template format with the release's example `docs/templates/mr-comment.md.tmpl`), and the pipeline inventory is its `glsec inventory` of [`sample/inventory.yml`](sample/inventory.yml). The GitLab example projects (gitlab.com/glsec-io/examples) scan the same file, and the screenshots on the reports page come from them, so keep the copies in sync. The screenshots on the GitLab Ultimate page come from the test project gitlab.com/glsec-io/ultimate-lab, which only members can see; they were taken by hand on 2026-10-27 and cropped to drop the sidebar, avatars and the GitLab Duo comment.

The performance page charts `data/benchmarks.jsonl` from glsec's [`benchmarks` branch](https://github.com/glsec/glsec/tree/benchmarks), which glsec's benchmark history workflow writes for every change to `main` and once for every release; the tags mark the releases. `perfStart` in `perf.go` sets the first release it shows.

## Building

Needs Go, git, curl, jq and the GitHub CLI, logged in or with `GH_TOKEN` set.

```sh
./scripts/build.sh                     # writes _site/
python3 -m http.server -d _site 8000   # http://localhost:8000
go test ./...
```

The built site is checked too (`.github/site-checks/`): on every pull request axe for accessibility, html-validate and stylelint, and `go test` checks title, description, canonical URL, one `h1` and the sitemap of every page. Lighthouse runs on `main` and weekly and wants 100 for accessibility and SEO, 90 for performance. To run them locally, `npm ci --ignore-scripts` in `.github/site-checks/` and see the steps in `site-checks.yml` and `lighthouse.yml`.

The build fails on a rule doc whose first line isn't `# GLxxx — Title`, on a relative link that leaves the glsec repository, and on any internal link without a page.

## Deployment

`.github/workflows/deploy.yml` publishes to GitHub Pages on every push to `main`, once a day, on `workflow_dispatch` and on a `glsec-release` repository dispatch.

To change rule text, edit the doc in [glsec](https://github.com/glsec/glsec/tree/main/docs/rules). It appears here with the next release.

## License

Apache-2.0, like glsec.
