# Evidence not copied into this archive

These items exist outside ordinary git blobs. They were not copied here, either because they could
not be read from this environment or because they are not needed to restore the cleaned-up files.
They remain where they are; nothing in the cleanup touches them.

| Item | Where it lives | Why it is not copied |
| --- | --- | --- |
| Pull request descriptions, review threads and bot reviews (including #17, #44-#53) | GitHub | Not part of the removed files; they remain on GitHub. |
| GitHub Actions logs and build artifacts | GitHub Actions | Retention-limited; this environment cannot download artifacts. |
| PEP 740 provenance for the 1.0.0b1 files | PyPI integrity API | The API returned HTTP 404 for both files: 1.0.0b1 has no published attestations. Recorded in pypi-1.0.0b1-files.json. |
| Branch protection, environment reviewers, Trusted Publisher settings | GitHub and PyPI settings | Not readable from this environment. |
| Off-repository evidence held by the owner (signed or timestamped originals) | Owner's own storage | Outside this repository; not accessed. Nothing here alters it. |
