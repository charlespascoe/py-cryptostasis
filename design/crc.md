EncryptedArchiveIndex
---------------------
* Knows
  * Archive Version
  * Password Salt
  * Master Key Hash
  * Encrypted Index MAC
  * Encrypted Index
* Does
  * Loads and parses index from disk
  * Verifies Master Key
  * Verifies index integrity
  * Decrypts index
  * Save index to disk

ArchiveIndex
------------
* Knows
  * All data about the encrypted archives
* Does
  * Generates a new unique archive ID
  * Adds a new archive entry to the index
  * Parse the archive index
  * Serialise the archive index for encryption

ArchiveEntry
------------
* Knows
  * The Archive ID
  * The Archive's unique name
  * The Archive's encryption key and tweak
  * Hash of the encrypted archive
* Does
  * Parse an entry from the decrypted archive
  * Serialise itself to be encrypted

Cipher
------
* Knows
  * Key and Tweak (within Threefish implementation)
* Does
  * Adds/removed PKCS#7 padding
  * Encrypts/Decrypts a block of data
  * Encrypts/Decrypts an arbitrary blob of data

MessageAuthenticationCodeGenerator
----------------------------------
* Knows
  * The

