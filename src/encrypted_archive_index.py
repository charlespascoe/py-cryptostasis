from cipher import Cipher
import os
import skein
from archive_index import ArchiveIndex
from consts import *
import log
import stat

class ArchiveIndexException(Exception):
    def __init__(self, message):
        super().__init__(message)


class IndexCorruptException(ArchiveIndexException):
    def __init__(self, path, reason=None):
        message = 'Index corrupt: {}'.format(path)

        if reason is not None:
            message += ' ({})'.format(reason)

        super().__init__(message)


class UnknownIndexVersionException(ArchiveIndexException):
    def __init__(self, path, version):
        super().__init__('Unknown index version: {} ({})'.format(version, path))
        self.version = version
        self.path = path


class EncryptedArchiveIndex:
    def __init__(self, path):
        log.debug(self, 'EncryptedArchiveIndex.__init__({})'.format(path))
        self.path = os.path.abspath(os.path.expanduser(path))
        self.version = None
        self.password_salt = None
        self.master_key = None
        self.master_key_hash = None
        self.encrypted_index_mac = None
        self.tweak = None
        self.encrypted_index = None

    def exists(self):
        exists = os.path.isfile(self.path)
        log.debug(self, 'Index file {} does {}exist'.format(self.path, '' if exists else 'not '))
        return exists

    def create_new_index(self):
        log.verbose(self, 'Creating new archive index')
        return ArchiveIndex(self)

    def save(self):
        data = bytes([VERSION]) + self.password_salt + self.master_key_hash + self.encrypted_index_mac + self.tweak + self.encrypted_index

        directory = os.path.dirname(self.path)

        if not os.path.isdir(directory):
            log.verbose(self, '{} directory does not exist, creating...'.format(directory))
            os.mkdir(directory)

        log.verbose(self, 'Writing data to {}'.format(self.path))
        with open(self.path, 'wb') as f:
            f.write(data)
            f.flush()
        log.verbose(self, 'Done!')

        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)

    def load(self):
        data_buf = None

        with open(self.path, 'rb') as f:
            data_buf = f.read()

        if len(data_buf) < (1 + PASSWORD_SALT_LENGTH + MASTER_KEY_HASH_LENGTH + ENCRYPTED_INDEX_MAC_LENGTH + TWEAK_LENGTH + MIN_ENCRYPTED_INDEX_LENGTH):
            raise IndexCorruptException(self.path)

        pos = 0

        self.version = int(data_buf[pos])

        if self.version != VERSION:
            raise UnknownIndexVersionException(self.path, self.version)

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

        log.debug(self, 'Computed master key hash: {}'.format(log.format_bytes(master_key_hash)))
        log.debug(self, 'Stored master key hash:   {}'.format(log.format_bytes(self.master_key_hash)))

        return master_key_hash == self.master_key_hash

    def verify_index_integrity(self, master_key):
        signature_key = master_key[CIPHER_KEY_LENGTH : ]

        hasher = skein.skein1024(key=signature_key)

        hasher.update(self.tweak)
        hasher.update(self.encrypted_index)

        encrypted_index_mac = hasher.digest()

        log.debug(self, 'Computed index MAC: {}'.format(log.format_bytes(encrypted_index_mac)))
        log.debug(self, 'Stored index MAC:   {}'.format(log.format_bytes(self.encrypted_index_mac)))

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
