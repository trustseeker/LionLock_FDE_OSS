# Publishing a beta release

## Current status

`1.0.0b2` was published to PyPI on 25 November 2026 (AEDT) from tag `v1.0.0b2`, commit
`efa1e53`, by the
[publish workflow](https://github.com/trustseeker/LionLock_FDE_OSS/actions/runs/45480304575)
after a maintainer approved the `pypi` deployment. It includes everything in
[CHANGELOG.md](../CHANGELOG.md). The files on PyPI were read back and match an independent
reproducible build of that commit, and PyPI's provenance names this repository, `publish.yml` and
the `pypi` environment:

- wheel `lionlock-1.0.0b2-py3-none-any.whl`: sha256
  `878de55029449acb5298d82db8158355e989e500106075eadbbe880fa9873f85`
- sdist `lionlock-1.0.0b2.tar.gz`: sha256
  `0ccad9860ef67770f1247a1b987014b0c71a5ff78d5fa42da9524e304dd9bda9`

The [README](../README.md) is also the PyPI project description, which cannot change after
upload, so it leads with the PyPI command. An earlier pre-release source commit,
`05434565`, also declared `1.0.0b2`; it lacks the November 2026 fixes and must not be used.

## Before creating the release

1. Select the exact reviewed commit. Check for newer changes before tagging; do not move an
   existing release tag. Use Python 3.12, as pinned in `.python-version`.
2. Run `make setup` and `make verify CHANGED_SINCE=origin/main`. Require `RESULT: PASS`, and
   inspect skipped tests and the verification report. Do not refresh the harness lock, baselines
   or goldens to conceal a failure. The normal environment omits optional SQLAlchemy tests.
3. In a separate clean build environment with the Python in `.python-version`, install
   `build==1.6.1` and `twine==7.0.0`, then run `python scripts/reproducible_build.py dist` and
   `python -m twine check --strict dist/*`. Record the sha256 of both files: the workflow builds
   with the same script, so its artifact must have the same hashes. A plain `python -m build`
   does not reproduce them.
4. Confirm `pyproject.toml`, wheel and sdist metadata all declare `1.0.0b2`, both CLI entry
   points are present, and the intended tag is exactly `v1.0.0b2`.
5. Install the built wheel in a fresh environment outside the checkout. Using that environment's
   Python, run `python -m pip check`, `python "$REPO/scripts/release_smoke.py" 1.0.0b2` where
   `$REPO` is the checkout's absolute path (the README scoring example and version checks),
   `python -m lionlock.sample_data`, `lionlock-telemetry --help` and `lionlock-sim --help`. Check
   `importlib.metadata.version('lionlock')`. Use synthetic databases for preservation and receiver
   tests; never run release validation against a tester's existing telemetry data.
6. Confirm the actual GitHub `pypi` environment still requires a maintainer reviewer, and that
   PyPI's Trusted Publisher configuration matches the repository's **current** owner
   `trustseeker`, repository `LionLock_FDE_OSS`, workflow `publish.yml`, and environment
   `pypi`. Workflow comments alone do not establish those settings. Do not replace Trusted
   Publishing with an API token.

   This step previously named owner `thruthseeker`, which the account no longer uses. GitHub
   redirects the old owner for web and git traffic, so clones and links keep working and the
   rename is easy to miss, but Trusted Publishing matches the OIDC `repository_owner` claim
   exactly and does not follow a rename. A configuration still naming the old owner rejects
   the upload after the release has already been published. Check PyPI before tagging.

## Publish through the existing workflow

1. Create the `v1.0.0b2` tag at the checked commit and publish a GitHub **pre-release**. Include
   the b2 fixes and upgrade requirements below. The workflow triggers on `release: published`;
   pushing a tag alone does not publish to PyPI.
2. Inspect the `publish` workflow's build job. It must pass the tag/version check and produce
   the `dist` artifact containing the wheel and sdist. Inspect that artifact's versions and
   checksums before approving; local build success is not proof of the workflow artifact.
3. An authorised maintainer approves the waiting `pypi` environment deployment. The publish job
   downloads the build artifact and uses its OIDC identity to upload it. Preserve this approval
   gate; do not bypass it or grant upload rights to the build job.
4. Require a successful publish job. Independently verify
   `https://pypi.org/pypi/lionlock/1.0.0b2/json`, including non-yanked distribution files, and
   download/install with no cache from `https://pypi.org/simple` in a fresh environment.
   Match the downloaded distribution hashes against the approved artifact. Repeat the version,
   dependency and CLI checks and the README example outside the source tree.
5. Only after that succeeds, update the receiver instructions and site to lead with the PyPI
   command, remove the pending-publication notices, and record the release/workflow links.
   Keep the compatibility warnings. If publishing fails, retain the verified source fallback
   and report the failure without claiming that the package is available.

## Upgrade requirements for the release notes

- Back up existing local logs, SQL telemetry databases and receiver data before upgrading.
  Stop writers or use a consistent SQLite backup that includes committed WAL contents; verify
  the backup before changing the running installation.
- **Upgrade and validate receivers before clients.** A receiver must admit `1.0.0b2` before
  clients send snapshots with that label. Require tokens on internet-facing endpoints; anonymous
  per-install rate limits are bypassable.
- Native `sqlite:///...` initialization preserves supported tables and rows. A known keyed
  pre-auth schema gains two nullable authentication columns. Extra custom columns and unknown
  layouts are refused without mutation and need a separately reviewed manual migration.
  Never drop, rebuild, rename or delete existing telemetry tables to force compatibility.
- This preservation change does not cover SQLAlchemy URI forms such as
  `sqlite+pysqlite:///...`, PostgreSQL or Trust Overlay initializers. An unsupported receiver
  warehouse is also refused unchanged; retain it and its backup if using a new data directory.
- The b2 fixes keep false-like upload settings disabled, reject negative row limits and key
  authenticated receiver rate limits by token. Review configuration during the upgrade, and
  leave uploads disabled unless the operator explicitly opts in.
