---
title: "Your GitLab CI includes probably aren't pinned the way you think"
description: "Two GitLab CI constructs look pinned and aren't: an include with no ref floats to a moving branch, and a component on @~latest drifts. Why that is the poisoned-pipeline path, and how to pin."
date: 2026-11-11
slug: gitlab-ci-include-pinning
summary: "An include without a ref and a component on a floating version both decide which code runs in your pipeline, and both can change with no diff in your repository."
---

Two things in a `.gitlab-ci.yml` look pinned and are not. Both decide which code runs in your pipeline, and both can change without a single line changing in your repository.

The first is an `include:` that names a project but no `ref`:

```yaml
include:
  - project: my-org/ci-templates
    file: /build.yml
```

GitLab resolves that to the current tip of the template project's default branch. Whoever pushes to that branch changes what your pipeline runs on its next execution. There is no version in the line, so nothing warns you, and there is no diff in your own history to review.

The second is a catalog component on a floating version:

```yaml
include:
  - component: gitlab.com/my-org/ci/[email protected]
```

`@~latest` and a bare major like `@1` both resolve to the latest matching release at pipeline start. A new release of the component, whether from its maintainer or from someone who compromises it, runs in your pipeline the next time you push.

In both cases the line reads as if it names a version. That is the trap. This is the poisoned-pipeline path: the upstream changes, your next run executes the new thing, and the change never shows up in a review of your own repository.

The fix is to pin to something immutable. A full tag is better than a branch, and a commit SHA is better than a tag, because a tag can be moved. Pin the project include to a SHA in its `ref`, and pin the component to an exact release or a SHA instead of `~latest` or a bare major.

The same class sits one layer down, inside the scripts. The LiteLLM compromise earlier this year started with a single unpinned install: an `apt-get install` with no version pulled a trojanised build that took the job's CI credentials. Any install that resolves "the latest" at run time is a candidate: `apt-get install <pkg>` with no version, `npx -y`, `pip install <pkg>` with no constraint, a `curl | sh` of an install script. Pin the version, or vendor the tool.

You can find most of this by eye. Grep for `include:` blocks without a `ref`, for `@~latest` and `@1`, and for installs with no version. [glsec](https://github.com/glsec/glsec) checks them as rules: [GL003](/rules/GL003/) for an include with a mutable or missing ref, [GL041](/rules/GL041/) for an unpinned component, and [GL022](/rules/GL022/) for an install without a version pin. It also flags the sharper variant where a CI variable is interpolated into the include target ([GL084](/rules/GL084/)), so whoever controls that variable chooses which configuration loads.

None of this needs the tool. The point is that "looks pinned" and "is pinned" are different in GitLab CI, and the gap is exactly where a supply-chain change gets in.

Disclosure: I maintain glsec.
