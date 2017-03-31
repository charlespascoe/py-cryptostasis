*Cryptostasis* - Encrypted Archive Management Tool
==================================================

Cryptostasis is designed to simplify encryption key management for archive files in long-term storage.

It is currently in development, and thus subject to breaking changes. Please feel free to try it and give feedback.

High-level summary
------------------

Cryptostasis works by maintaining an index file - encrypted by a master password - that stores all of the randomly-generated encryption keys used to encrypt various archives - a bit like LastPass, but for encryption keys.

By having an encrypted index file, it will remove the problem of forgotten passwords for old archives, and also prevents password cracking on the archive file itself.

Currently, Cryptostasis uses Threefish-1024 for encryption and Skein-1024 for hashing/HMACs. The cipher was chosen due to its large key space and modern construction (as a tweakable block cipher), and so is suitable for encrypting data that needs to exist for a long time into the future.

Additionally, Argon2i with high complexity parameters is used for deriving the master key for the index file, which when combined with a long and complex password, is very difficult to brute-force.

Dependencies
------------

* Python 3 (known to work on 3.5)
* pip3
* pyskein (`pip3 install pyskein`)
* argon2-cffi (`pip3 install argon2-cffi`)

Install both dependencies by running `pip3 install -r requirements.txt`

Usage
-----

All archive entries in the index have unique names, specified when the archive is encrypted.

You will be prompted on first use to set a password.

To encrypt an archive:

`$ cryptostasis encrypt archive-name -f archive.tar -o encrypted-archive.bin`

If `-f` or `--input-file` isn't specified, then it will read from stdin. If `-o` or `--output-file` isn't specified, then it will write to stdout.

To decrypt an archive:

`$ cryptostasis decrypt -f encrypted-archive.bin -o archive.tar`

To list all entries in the archive index:

`$ cryptostasis list`

To change the index encryption password:

`$ cryptostasis passwd`

When changing the password, you can also set the key derivation function (KDF) complexity parameters to make brute force or dictionary attacks much harder.

Platform Support
----------------

Cryptostasis is being developed on 64-bit Ubuntu and the dependencies work on 64/32-bit OSes, so it should work on other Linux distros and Mac - if not, please raise an issue.

If it works on Windows, great. If not, please don't complain - Windows isn't a priority for me.
