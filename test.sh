#!/usr/bin/env bash
set -e

export ASAN_OPTIONS=detect_stack_use_after_return=1:abort_on_error=1
#:fast_unwind_on_malloc=0:detect_leaks=0

if true; then
    echo "====== Rebuilding ==========================="
    make clean || true
    ./bootstrap.sh
    ./configure \
	PQLIBPATH="$HOME/opt/kyber/lib" \
	STD=c++17 \
	CXXFLAGS="-fsanitize=address -fsanitize=undefined"
    make -j$(nproc)
    make check
fi
rm -f scratch/*

echo "====== Generate key and encrypt ============="
./testspect_gen.ex ./kybertest_keygen -o scratch/testkey
ls -l scratch/testkey*
./kybertest_encrypt -r scratch/testkey.pub < testdata/plain.txt > scratch/enc2
ls -l scratch/enc2

echo "====== Test decrypt ========================="
./testspect.ex ./kybertest_decrypt scratch/testkey.priv scratch/enc2

echo "====== Upgrading old keys ==================="
rm -f testdata/testkey_v1_key{0,1}.priv
./kybertest_keygen -P -u testdata/testkey_v0_key0.priv -o testdata/testkey_v1_key0
./extra/pwwrap.ex \
    ./kybertest_keygen -u testdata/testkey_v0_key1.priv -o testdata/testkey_v1_key1
cp testdata/testkey_v{0,1}_key0.pub
cp testdata/testkey_v{0,1}_key1.pub

echo "====== Backwards compatibility check ========"
# Backwards compat check.
CORRECT="$(sha1sum testdata/plain.txt | awk '{print $1}')"
for key in 0 1 2 3 4 5; do
    for i in testdata/encrypted*key${key?}.kyb; do
	for priv in $(ls testdata/testkey_v?_key${key?}.priv); do
	    ./testspect.ex ./kybertest_decrypt "${priv?}" "${i?}" \
		|| (
		echo "Failed for $key $i"
		false)
	done
    done
done

echo "============================================="
echo "OK"
