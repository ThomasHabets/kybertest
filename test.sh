#!/usr/bin/env bash
set -e

export ASAN_OPTIONS=detect_stack_use_after_return=1:abort_on_error=1
#:fast_unwind_on_malloc=0:detect_leaks=0

make clean || true
./bootstrap.sh
./configure \
    PQLIBPATH="$HOME/opt/kyber/lib" \
    STD=c++17 \
    CXXFLAGS="-fsanitize=address -fsanitize=undefined"
make -j
make check
rm -f scratch/*

echo "============================================="
echo "Choose any password"
./kybertest_keygen -F 1 -o scratch/testkey
./kybertest_encrypt -F 1 -r scratch/testkey.pub < README.md > scratch/enc2
ls -l scratch/enc2

echo "============================================="
echo "Enter it again"
./kybertest_decrypt -k scratch/testkey.priv < scratch/enc2 > scratch/dec2
#sha1sum README.md scratch/dec2
cmp README.md scratch/dec2

echo "============================================="
echo "Backwards compatability check"
echo "Enter 'secret' as the password every time you're asked"
# Backwards compat check.
CORRECT="$(sha1sum testdata/plain.txt | awk '{print $1}')"
for key in 0 1 2 3; do
    for i in testdata/encrypted*key${key?}.kyb; do
	KEYFN="$(ls testdata/testkey_v?_key${key?}.priv)"
	T="$(./kybertest_decrypt -k "${KEYFN?}" < $i | sha1sum - | awk '{print $1}')"
	if [[ ! $T = $CORRECT ]]; then
	    echo "mismatch for key ${KEYFN?} input ${i?}"
	    exit 1
	fi
    done
done

echo "============================================="
echo "OK"
