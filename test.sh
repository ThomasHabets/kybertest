#!/usr/bin/env bash
set -e

make -j
make check
rm -f scratch/*
./kybertest_keygen -Po scratch/testkey
./kybertest_encrypt -F 1 -r scratch/testkey.pub < README.md > scratch/enc2
ls -l scratch/enc2
./kybertest_decrypt -k scratch/testkey.priv < scratch/enc2 > scratch/dec2
sha1sum README.md scratch/dec2
