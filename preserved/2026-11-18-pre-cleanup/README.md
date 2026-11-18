# LionLock pre-cleanup archive, 18 November 2026

This archive preserves every repository item that the 1.0.0b2 cleanup (decision D4) removes,
replaces, relocates or edits, as it stood at source commit
`b93ac367d3f5c5d662b49ddb4b2ea0ee8e01afa6` on `main`. It was made before any cleanup change.

## Contents

- `originals/` - the exact bytes of each item at the source commit, at its original path.
- `provenance/` - the commit history of each item (commit, author date, subject).
- `repo-tree.tsv` - every tracked file at the source commit, with its git blob id and SHA-256.
- `refs.tsv` - every branch and tag on the GitHub remote when the archive was made.
- `external/` - published 1.0.0b1 metadata from PyPI and GitHub, and a list of evidence not copied.
- `MANIFEST.json` - the source commit, each item's planned action, size, SHA-256 and git blob id.
- `SHA256SUMS` - the SHA-256 of every other file in this directory.

## Verify

    sha256sum -c SHA256SUMS
    git cat-file -e b93ac367d3f5c5d662b49ddb4b2ea0ee8e01afa6   # in any clone of the repository

Each original also matches its git blob id: `git hash-object originals/<path>` prints the
`git_blob` recorded in MANIFEST.json.

## Restore an item

Copy it back from `originals/`, or take it from git history:

    git checkout b93ac367d3f5c5d662b49ddb4b2ea0ee8e01afa6 -- <path>

## Limits

SHA-256 values and git ids establish byte integrity only. They do not establish authorship or the
date an idea was conceived. Commit dates are written by the committer's machine. Nothing in this
archive alters any signed or timestamped original held elsewhere.

A full bundle of every branch is kept separately, in restricted storage, because one branch carries
material that is not meant for wider publication. It is not part of this public archive.
