#!/usr/bin/env bash
set -e

export ASAN_OPTIONS=detect_stack_use_after_return=1:abort_on_error=1
#:fast_unwind_on_malloc=0:detect_leaks=0

if false; then
    make clean || true
    ./bootstrap.sh
    ./configure \
	PQLIBPATH="$HOME/opt/kyber/lib" \
	STD=c++17 \
	CXXFLAGS="-fsanitize=address -fsanitize=undefined"
    make -j
    make check
fi
rm -f scratch/*

echo "============================================="
echo "Choose any password"
./testspect_gen.ex ./kybertest_keygen -o scratch/testkey
./kybertest_encrypt -F 1 -r scratch/testkey.pub < testdata/plain.txt > scratch/enc2
ls -l scratch/enc2

echo "============================================="
echo "Enter it again"
./testspect.ex ./kybertest_decrypt scratch/testkey.priv scratch/enc2

echo "============================================="
echo "Backwards compatability check"
echo "Enter 'secret' as the password every time you're asked"
# Backwards compat check.
CORRECT="$(sha1sum testdata/plain.txt | awk '{print $1}')"
for key in 0 1 2 3; do
    for i in testdata/encrypted*key${key?}.kyb; do
	KEYFN="$(ls testdata/testkey_v?_key${key?}.priv)"
	T="$(./testspect.ex ./kybertest_decrypt "${KEYFN?}" $i)"
    done
done

echo "============================================="
echo "OK"
