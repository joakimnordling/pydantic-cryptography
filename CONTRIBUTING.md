# Contributing

Thanks for your interest! Bug reports, questions and pull requests are welcome on
[GitHub](https://github.com/joakimnordling/pydantic-cryptography). For anything bigger than a
small fix, please open an issue first so we can agree on the approach.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Please report
security problems privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Setup

The project uses [uv](https://docs.astral.sh/uv/) for everything.

```bash
git clone https://github.com/joakimnordling/pydantic-cryptography.git
cd pydantic-cryptography
uv sync                    # creates .venv with the package and all dev tools
uv run pre-commit install  # runs the checks on every commit
```

## Running the tests

```bash
uv run pytest
```

The tests generate their keys (every supported kind) once per run; no key is stored in the
repository, except an encrypted OpenSSH test key. The JWKs are checked against the RFC examples,
and against [joserfc](https://jose.authlib.org/), an independent implementation.

CI also runs the tests on every supported Python version, and with the lowest and the newest
allowed versions of the dependencies. To try the lowest versions locally:

```bash
UV_RESOLUTION=lowest-direct uv sync
uv run --no-sync pytest     # --no-sync: `uv run` would re-resolve with the locked versions
```

(This rewrites `uv.lock`; run `git checkout uv.lock && uv sync` afterwards.)

## Type checking

The package code and the typing tests are checked with mypy, pyright and ty, all in strict mode.
All three must pass:

```bash
uv run mypy
uv run pyright
uv run ty check
uv run mypy --config-file tests/typing/mypy-pydantic-plugin.ini  # as seen with Pydantic's plugin
```

`tests/typing/` contains code as a user of the package would write it. It's type-checked, never
run. Lines that must be reported as errors are marked `# type: ignore`, and the checkers are set up
to report unneeded ignores. So if a planted error stops being detected, the check fails.

## Linting and formatting

[ruff](https://docs.astral.sh/ruff/) does both, and runs as part of pre-commit. Pre-commit also checks
the GitHub Actions workflows: [zizmor](https://docs.zizmor.sh/) for security problems, and
[actionlint](https://github.com/rhysd/actionlint) for mistakes, including shellcheck on the `run:`
scripts. actionlint's first run takes a minute or so, while pre-commit downloads Go and builds it.
To run all hooks by hand:

```bash
uv run pre-commit run --all-files
```

## Releasing

Publishing happens on GitHub Actions through PyPI trusted publishing (no tokens), when a version tag
is pushed. `main` only accepts changes through pull requests, so the release commit goes through one
too, and the tag goes on `main` after it's merged:

```bash
git switch -c release-0.1.0
uv version 0.1.0          # or e.g. 0.1.0a1 for a pre-release
# move the CHANGELOG's Unreleased entries under "## [0.1.0] - <date>"
git commit -am "Release 0.1.0" && git push -u origin release-0.1.0
# open a PR, wait for CI, merge it; then:
git switch main && git pull
git tag v0.1.0 && git push origin v0.1.0
```

The workflow checks that the tagged commit is on `main` and that the tag matches the version in
`pyproject.toml`, builds and checks the package, publishes it to PyPI and creates a GitHub release
with that version's changelog section and a link to the full changelog.
Versions with `a`, `b` or `rc` in them are marked as pre-releases. Installers skip those in favour
of stable versions, but note that they do install a pre-release when the project has no stable
release at all.

## Guidelines

- Test coverage (lines and branches) stays at 100%: `uv run pytest --cov` fails below that. Mark
  code that truly can't be reached in a test with `# pragma: no cover`, with a comment why.
- Every bug fix or behaviour change comes with a test.
- Key material must never end up in a `repr`, a `str`, a JSON dump or a validation error (which
  Pydantic fills with the input, and which ends up in logs). Check it with `assert_not_shown()` from
  `tests/helpers.py`, and add any new way in to `test_errors_never_show_the_input` in
  `tests/test_loading.py`.
- Keep the public API small; everything else is underscore-prefixed, or in an underscore module.
- Don't rely on private Pydantic or cryptography APIs.
- The minimum cryptography version is one without known vulnerabilities: when a release fixes a
  security problem, raise it to that release rather than keep supporting the older ones.
- Multi-line docstrings start their text on the line after the opening quotes.
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- The README examples are run by the tests (`tests/test_readme.py`), so keep them working.
