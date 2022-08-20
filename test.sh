#!/usr/bin/env bash
set -e

make -j
make check
rm -f scratch/*
./kybertest_keygen -F 1 -o scratch/testkey
./kybertest_encrypt -F 1 -r scratch/testkey.pub < README.md > scratch/enc2
ls -l scratch/enc2
./kybertest_decrypt -k scratch/testkey.priv < scratch/enc2 > scratch/dec2
sha1sum README.md scratch/dec2


# Backwards compat check.
for key in 0 1 2 3; do
    for i in testdata/encrypted*key${key?}.kyb; do
	./kybertest_decrypt -k testdata/testkey_v?_key${key?}.priv < $i | sha1sum -
    done
done

echo "----------"
echo "OK"
