from cipher import Cipher
import os
import skein
from archive_index import ArchiveIndex
from consts import *
import log

class ArchiveIndexException(Exception):
    def __init__(self, message):
        super(message)


class IndexCorruptException(ArchiveIndexException):
    def __init__(self, path, reason=None):
        message = 'Index corrupt: {}'.format(path)

        if reason is not None:
            message += ' ({})'.format(reason)

        super(message)


class UnknownIndexVersionException(ArchiveIndexException):
    def __init__(self, path, version):
        super('Unknown index version: {} ({})'.format(version, path))
        self.version = version
        self.path = path


class EncryptedArchiveIndex:
    def __init__(self, path):
        log.debug('EncryptedArchiveIndex.__init__({})'.format(path))
        self.path = os.path.expanduser(path)
        self.version = 1
        self.password_salt = None
        self.master_key = None
        self.master_key_hash = None
        self.encrypted_index_mac = None
        self.tweak = None
        self.encrypted_index = None

    def exists(self):
        exists = os.path.isfile(self.path)
        log.debug('Index file {} does {}exist'.format(self.path, '' if exists else 'not '))
        return exists

    def create_new_index(self):
        log.verbose('Creating new archive index')
        return ArchiveIndex(self)

    def save(self):
        data = bytes([1]) + self.password_salt + self.master_key_hash + self.encrypted_index_mac + self.tweak + self.encrypted_index

        directory = os.path.dirname(self.path)

        if not os.path.isdir(directory):
            log.verbose('{} directory does not exist, creating...'.format(directory))
            # TODO: need to check if file has directory name
            os.mkdir(directory)

        log.verbose('Writing data to {}'.format(self.path))
        with open(self.path, 'wb') as f:
            f.write(data)
            f.flush()
        log.verbose('Done!')

    def load(self):
        data_buf = None

        with open(self.path, 'rb') as f:
            data_buf = f.read()

        if len(data_buf) < (1 + PASSWORD_SALT_LENGTH + MASTER_KEY_HASH_LENGTH + ENCRYPTED_INDEX_MAC_LENGTH + TWEAK_LENGTH + MIN_ENCRYPTED_INDEX_LENGTH):
            raise IndexCorruptException(self.path)

        pos = 0

        if data_buf[pos] != VERSION:
            raise UnknownIndexVersionException(self.path, int(data_buf[pos]))

        pos += 1

        self.password_salt = data_buf[pos : pos + PASSWORD_SALT_LENGTH]
        pos += PASSWORD_SALT_LENGTH

        self.master_key_hash = data_buf[pos : pos + MASTER_KEY_HASH_LENGTH]
        pos += MASTER_KEY_HASH_LENGTH

        self.encrypted_index_mac = data_buf[pos : pos + ENCRYPTED_INDEX_MAC_LENGTH]
        pos += ENCRYPTED_INDEX_MAC_LENGTH

        self.tweak = data_buf[pos : pos + TWEAK_LENGTH]
        pos += TWEAK_LENGTH

        self.encrypted_index = data_buf[pos : ]

    def verify_master_key(self, master_key):
        hasher = skein.skein1024()

        hasher.update(master_key)

        master_key_hash = hasher.digest()

        log.debug('Computed master key hash: {}'.format(master_key_hash.hex()))
        log.debug('Stored master key hash:   {}'.format(self.master_key_hash.hex()))

        return master_key_hash == self.master_key_hash

    def verify_index_integrity(self, master_key):
        signature_key = master_key[CIPHER_KEY_LENGTH : ]

        hasher = skein.skein1024(key=signature_key)

        hasher.update(self.tweak)
        hasher.update(self.encrypted_index)

        encrypted_index_mac = hasher.digest()

        log.debug('Computed index MAC: {}'.format(encrypted_index_mac.hex()))
        log.debug('Stored index MAC:   {}'.format(self.encrypted_index_mac.hex()))

        return encrypted_index_mac == self.encrypted_index_mac

    def decrypt_index(self, master_key):
        self.master_key = master_key

        encryption_key = master_key[ : CIPHER_KEY_LENGTH]

        cipher = Cipher(encryption_key, self.tweak)

        decrypted_index = cipher.decrypt(self.encrypted_index)

        return ArchiveIndex(self, decrypted_index)

    def update_master_key(self, master_key):
        self.master_key = master_key

        hasher = skein.skein1024()

        hasher.update(master_key)

        self.master_key_hash = hasher.digest()

    def encrypt_index(self, index_buf):
        encryption_key = self.master_key[ : CIPHER_KEY_LENGTH]
        signature_key = self.master_key[CIPHER_KEY_LENGTH : ]
        self.tweak = os.urandom(TWEAK_LENGTH)

        cipher = Cipher(encryption_key, self.tweak)
        hasher = skein.skein1024(key=signature_key)

        self.encrypted_index = cipher.encrypt(index_buf)

        hasher.update(self.tweak)
        hasher.update(self.encrypted_index)

        self.encrypted_index_mac = hasher.digest()