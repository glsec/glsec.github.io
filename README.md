# glsec.github.io

Source of <https://glsec.github.io>, the website and rule reference for [glsec](https://github.com/glsec/glsec).

The rule pages are generated from `docs/rules.md` and `docs/rules/GLxxx.md` in the glsec repository, at the latest release tag, so the site always describes the version people can install. The OWASP page sorts the rules from that release's `glsec list --format json` into the ten OWASP CI/CD risks. The example on the home page and the example reports are the output of that release's binary on [`sample/.gitlab-ci.yml`](sample/.gitlab-ci.yml), in every format.

## Building

Needs Go, git, curl, jq and the GitHub CLI, logged in or with `GH_TOKEN` set.

```sh
./scripts/build.sh                     # writes _site/
python3 -m http.server -d _site 8000   # http://localhost:8000
go test ./...
```

The build fails on a rule doc whose first line isn't `# GLxxx — Title`, on a relative link that leaves the glsec repository, and on any internal link without a page.

## Deployment

`.github/workflows/deploy.yml` publishes to GitHub Pages on every push to `main`, once a day, on `workflow_dispatch` and on a `glsec-release` repository dispatch.

To change rule text, edit the doc in [glsec](https://github.com/glsec/glsec/tree/main/docs/rules). It appears here with the next release.

## License

Apache-2.0, like glsec.
