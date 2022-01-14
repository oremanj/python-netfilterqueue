#!/bin/bash

set -ex -o pipefail

pip install -U pip setuptools wheel
sudo apt-get install libnetfilter-queue-dev

# Cython is required to build the sdist...
pip install cython
python setup.py sdist --formats=zip

# ... but not to install it
pip uninstall -y cython
pip install dist/*.zip

pip install -Ur test-requirements.txt

if [ "$CHECK_LINT" = "1" ]; then
    error=0
    if ! black --check setup.py tests; then
        cat <<EOF
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Formatting problems were found (listed above). To fix them, run

   pip install -r test-requirements.txt
   black setup.py tests

in your local checkout.

EOF
        error=1
    fi
    if [ "$error" = "1" ]; then
        cat <<EOF
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
    fi
    exit $error
fi

cd tests
pytest -W error -ra -v .
