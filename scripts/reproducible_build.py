"""Build the wheel and sdist of HEAD so that the files are byte-identical on every machine.

    python scripts/reproducible_build.py [outdir]        # default: dist/

The publish workflow runs this same script, so a maintainer who checks out the release commit
and runs it gets files with the same sha256 as the ones the workflow uploads.

What it fixes, and why each step is needed:

* It builds from `git archive HEAD`, not from the working tree: untracked or ignored files cannot
  leak in, and file modes and times do not depend on the checkout's umask or clone time.
* It sets SOURCE_DATE_EPOCH to the commit time, which fixes the timestamps inside the wheel.
* It pins umask to 022 for the build, because the wheel records file modes.
* The sdist is then rewritten with sorted entries, fixed ownership, modes and times, and a gzip
  header without a timestamp. setuptools leaves the times of generated files (the egg-info
  directory) at build time, so two builds of the same commit otherwise differ.

Remaining limit: archives are deflate-compressed, so the bytes also depend on the zlib build in
the Python that runs this. Use the Python pinned in .python-version (the workflow does).
Requires `build` (the workflow pins its version) and the backend pinned in pyproject.toml.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def normalize_sdist(path: Path, epoch: int) -> None:
    """Rewrite an sdist so its bytes depend only on its members' names and contents."""
    with tarfile.open(path, "r:gz") as src:
        members = sorted(src.getmembers(), key=lambda m: m.name)
        payload = {m.name: src.extractfile(m).read() for m in members if m.isfile()}  # type: ignore[union-attr]
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as dst:
            for m in members:
                info = tarfile.TarInfo(m.name)
                info.mtime = epoch
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.pax_headers = {}
                if m.isdir():
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    dst.addfile(info)
                elif m.isfile():
                    info.size = len(payload[m.name])
                    info.mode = 0o755 if m.mode & 0o100 else 0o644
                    dst.addfile(info, io.BytesIO(payload[m.name]))
                else:
                    raise SystemExit(f"unexpected member type in sdist: {m.name}")
    path.write_bytes(buffer.getvalue())


def main(argv: list[str]) -> int:
    repo = Path(__file__).resolve().parents[1]
    outdir = Path(argv[1] if len(argv) > 1 else "dist").resolve()
    epoch = int(_git(repo, "log", "-1", "--pretty=%ct").decode().strip())
    os.umask(0o022)
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(epoch)}
    print(f"commit {_git(repo, 'rev-parse', 'HEAD').decode().strip()} SOURCE_DATE_EPOCH={epoch}")

    outdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "tree"
        tree.mkdir()
        archive = _git(repo, "archive", "--format=tar", "HEAD")
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(tree, filter="tar")
            else:  # older patch releases of 3.10 and 3.11 lack extraction filters
                tar.extractall(tree)
        built = Path(tmp) / "out"
        subprocess.run(
            [sys.executable, "-m", "build", "--outdir", str(built), str(tree)],
            check=True,
            env=env,
        )
        for sdist in built.glob("*.tar.gz"):
            normalize_sdist(sdist, epoch)
        for item in sorted(built.iterdir()):
            shutil.copy2(item, outdir / item.name)

    for item in sorted(outdir.iterdir()):
        print(hashlib.sha256(item.read_bytes()).hexdigest(), item.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
