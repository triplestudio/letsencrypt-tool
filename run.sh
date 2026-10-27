#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  echo "[1/2] 首次运行，正在创建 Python 运行环境..."
  python3 -m venv .venv
  echo "[2/2] 正在安装依赖 cryptography..."
  ./.venv/bin/python -m pip install -q --disable-pip-version-check -r requirements.txt
fi

exec ./.venv/bin/python app.py "$@"
