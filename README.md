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
* There is no authentication of decrypted data. Corrupt/interfered
  ciphertext will produce corrupt/interfered output. (this should be
  fixable before 1.0)
* CBC is not the greatest mode in the first place. (also fixable)
* TODO: add more reasons

## Deliberate design decisions

* One algorithm only. Kyber 1024 and AES-256-CBC in the first version.
* No compression. If the user wants to compress the input it's up to
  them, using their favourite tool.
  
## How to use it

```
./keygen -o mykey
cat secret.txt | gpg -e -r somebody@example.com | ./encrypt -r mykey.pub > secret.txt.gpg.kyb
cat secret.txt.gpg.kyb | ./decrypt -k mykey.priv | gpg -d > secret2.txt
```

## Installing dependency

```
git clone https://github.com/pq-crystals/kyber
cd kyber/ref
make shared
mkdir -p ~/opt/kyber/lib
cp *.so ~/opt/kyber/lib
```
