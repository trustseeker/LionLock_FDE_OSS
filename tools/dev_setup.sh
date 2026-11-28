#!/usr/bin/env sh
set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

VENV_PATH="${LIONLOCK_VENV_PATH:-$ROOT_DIR/.venv}"

if [ ! -d "$VENV_PATH" ]; then
  python -m venv "$VENV_PATH"
fi

. "$VENV_PATH/bin/activate"

pip install --upgrade pip
# Python 3.11's venv also installs its bundled setuptools, which has published advisories, so
# upgrade it if it is there. Python 3.12 and later install no setuptools, and none is added.
if pip show setuptools >/dev/null 2>&1; then
  pip install --upgrade setuptools
fi
pip install -e ".[dev]"

pytest -q
