#!/bin/bash

set -ex -o pipefail

pip install -U pip setuptools wheel
sudo apt-get install libnetfilter-queue-dev
python setup.py sdist --formats=zip
pip install dist/*.zip
pip install -r test-requirements.txt

cd tests
pytest -W error -ra -v .
