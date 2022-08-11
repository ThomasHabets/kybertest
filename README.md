# Kybertest

## What is it

Command line tool for encrypting and decrypting using quantum
resistant cryptography (or post-quantum, PQ), specifically Kyber.

## DO NOT DEPEND ON THIS

Only ever use this *on top of* another level of encryption, like GPG.

Reasons to not trust the kybertest layer:

* The author is not a professional cryptographer, but just another
  dangerous person who's read Applied Cryptography and some other
  stuff.
* Kyber (and all other PQ algorithms) is not as analyzed as
  traditional crypto like RSA.
* There is no authentication of decrypted data. Corrupt/interfered
  ciphertext will produce corrupt/interfered output. (this should be
  fixable before 1.0)
* CBC is not the greatest mode in the first place. (also fixable)
* TODO: add more reasons

## How to use it

Right now all the tools just use unencrypted pub/privkeys in the
current directory called `key.pub` and `key.priv`. Should be fixed
soon.

```
./keygen
cat secret.txt | gpg -e -r somebody@example.com | ./encrypt > secret.txt.gpg.kyb
cat secret.txt.gpg.kyb | ./decrypt | gpg -d > secret2.txt
```

## Installing dependency

```
git clone https://github.com/pq-crystals/kyber
cd kyber/ref
make shared
mkdir -p ~/opt/kyber/lib
cp *.so ~/opt/kyber/lib
```
