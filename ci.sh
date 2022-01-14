#!/bin/bash

set -ex -o pipefail

pip install -U pip setuptools wheel
sudo apt-get install libnetfilter-queue-dev

# Cython is required to build the sdist...
pip install cython
python setup.py sdist --formats=zip

# ... but not to install it
pip uninstall -y cython
python setup.py build_ext
pip install dist/*.zip

pip install -Ur test-requirements.txt

if [ "$CHECK_LINT" = "1" ]; then
    error=0
    black_files="setup.py tests netfilterqueue"
    if ! black --check $black_files; then
        error=$?
        black --diff $black_files
    fi
    mypy --strict -p netfilterqueue || error=$?
    ( mkdir empty; cd empty; python -m mypy.stubtest netfilterqueue ) || error=$?

    if [ $error -ne 0 ]; then
        cat <<EOF
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Problems were found by static analysis (listed above).
To fix formatting and see remaining errors, run:

   pip install -r test-requirements.txt
   black $black_files
   mypy --strict -p netfilterqueue
   ( mkdir empty; cd empty; python -m mypy.stubtest netfilterqueue )

in your local checkout.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
        exit 1
    fi
    exit 0
fi

cd tests
pytest -W error -ra -v .
