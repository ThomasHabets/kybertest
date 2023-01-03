# Kybertest

https://github.com/ThomasHabets/kybertest

## What is it

Command line tool for encrypting and decrypting using quantum
resistant cryptography (or post-quantum, PQ), specifically Kyber.

## DO NOT DEPEND ON THIS

Only ever use this *on top of* another level of encryption, like GPG.

Reasons to not trust the kybertest layer:

* The author is not a professional cryptographer, but just another
  dangerous person who's read Applied Cryptography and some other
  stuff, and is assembling crypto primitives like Kyber and AES.
* Kyber (and all other PQ algorithms) is not as analyzed as
  traditional crypto like RSA.
* TODO: add more reasons

## Deliberate design decisions

* One algorithm only. Kyber 1024 and AES-256-GCM in the first version.
* No compression. If the user wants to compress the input it's up to
  them, using their favourite tool.

## Installing

### Installing dependency

```
git clone https://github.com/pq-crystals/kyber
cd kyber/ref
make shared
cp *.so /usr/local/lib
```

### Building

```
./bootstrap.sh  # Only needed if taking source from git repo, not .tar.gz.
./configure
make
sudo make install
```

If you have the kyber library dependency in another directory then try e.g.:

```
./configure PQLIBPATH=$HOME/opt/kyber/lib
```

## How to use it

```
kybertest_keygen -o mykey
cat secret.txt | gpg -e -r somebody@example.com | kybertest_encrypt -r mykey.pub > secret.txt.gpg.kyb
cat secret.txt.gpg.kyb | kybertest_decrypt -k mykey.priv | gpg -d > secret2.txt
```

## File formats

### Encrypted data file format: Version 1

See [`doc/file_format_1.md`](doc/file_format_1.md).

### Public key file format

Public keys are just the header `KYBPUB00` for the version `0` format,
followed by the raw public key material.
