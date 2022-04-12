#!/bin/sh -e
python3 -m venv venv
. ./venv/bin/activate
python3 -m pip install pip-tools
pip-compile-multi --directory "./requirements"
python3 -m  pip install -r "./requirements/dev.txt"
python3 -m  pip install .
pytest
