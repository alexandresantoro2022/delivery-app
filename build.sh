#!/usr/bin/env bash
# exit on error
set -o errexit

pip install --upgrade pip
pip install -r requirements.txt

python -m flask db upgrade

echo "Build finalizado com sucesso!"

