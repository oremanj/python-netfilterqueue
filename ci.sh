#!/bin/bash

set -ex -o pipefail

pip install -U pip setuptools wheel
sudo apt-get install libnetfilter-queue-dev

python setup.py sdist --formats=zip
pip install dist/*.zip

if python --version 2>&1 | fgrep -q "Python 2.7"; then
    # The testsuite doesn't run on 2.7, so do just a basic smoke test.
    unshare -Urn python -c "from netfilterqueue import NetfilterQueue as NFQ; NFQ()"
    exit $?
fi

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
