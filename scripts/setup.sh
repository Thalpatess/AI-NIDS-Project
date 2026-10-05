#!/usr/bin/env bash
set -e

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r python/requirements.txt
python python/attack_simulator.py
python python/train_model.py
