#!/bin/sh -e
python3 -m venv venv || pyenv virtualenv 3.11.4 quart-login_3.11.4
. ./venv/bin/activate || . $(pyenv root)/versions/quart-login_3.11.4/bin/activate
python3 -m pip install pip-tools
python3 -m pip install pip-compile-multi
pip-compile-multi --directory "./requirements"
python3 -m  pip install -r "./requirements/dev.txt"
python3 -m  pip install .
pytest
