# EMET release checklist

A release is reproducible from the public surface. Every gate below must be green
before a tag is cut, and the published artifacts must re-derive after upload.

## Pre-flight gates (all must pass)

```sh
# 1. The implementations agree on the vector suite.
python conformance/run.py membrane.py                      # Python reference: 40/40
( cd impl/rust && rustc -O emet.rs -o emet ) && python conformance/run.py impl/rust/emet   # 40/40
python conformance/run.py impl/js/emet.js                  # Node.js: 40/40
( cd impl/go && go build -o emet emet.go ) && python conformance/run.py impl/go/emet        # Go: 35/40 (receipt/check not yet ported; SPEC s.17)

# 2. The Python behavior + delivery suite.
python -m pytest -q                                        # all green

# 3. Identity + hygiene.
python membrane.py selftest                                # emet_self_sha256= + legacy alias
git diff --check                                           # no whitespace errors on changed lines
```

Confirm: no secrets or `.env` in the tree; runtime state (`anchors.json`,
`*_log.jsonl`, `*.refused`) and build artifacts (`dist/`, `impl/**/emet*`) are
gitignored; `SPEC.md`, `README.md`, and `CHANGELOG.md` state the version honestly;
the independent, different-author re-derivability bar (SPEC section 12) is still
described as open (1.0.0 does not claim it met).

## Version bump (single source per site)

Bump in lockstep (they must agree): `SPEC.md` header, `README.md` version badge,
`SECURITY.md`, `COVERAGE.json`, `conformance/vectors.json` `spec_version`,
`adapters/*.py` `SPEC_VERSION`, `USAGE.md` illustrative receipt, `pyproject.toml`
`version`, `emet/report.py` `EMET_VERSION`/`SPEC_VERSION`, `emet/__init__.py`
`__version__`, and `impl/rust/Cargo.toml`. Add a `CHANGELOG.md` entry.

## Tag, push, release

```sh
git tag -a v1.0.0 -m "EMET 1.0.0 - frozen contract, four implementations"
git push origin main
git push origin v1.0.0
# GitHub release from the tag (gh):
gh release create v1.0.0 --title "EMET 1.0.0" --notes-file <(sed -n '/## 1.0.0/,/## 2026-06-29/p' CHANGELOG.md)
```

## PyPI (emet)

```sh
python -m build                          # sdist + wheel into dist/
python -m twine check dist/*             # metadata OK
python -m twine upload dist/*            # requires a PyPI API token
```

## Post-publish re-derivation (the release verifies itself)

```sh
python -m venv /tmp/emet-verify && . /tmp/emet-verify/bin/activate
pip install emet
emet selftest                                                   # re-derives its identity
python conformance/run.py "$(command -v emet)"                  # installed console script: 40/40
```

If the published artifact does not re-derive, the release is not done. EMET's only
credential is reproduction; a release that cannot be reproduced refutes itself.
