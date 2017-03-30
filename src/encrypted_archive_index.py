from cipher import Cipher
import os
import skein
from archive_index import ArchiveIndex
from consts import *
import log
import stat
from io import BytesIO
from key_deriver import KeyDeriver

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
        self.path = os.path.abspath(os.path.expanduser(path))
        self.version = None
        self.password_salt = None
        self.master_key = None
        self.master_key_hash = None
        self.encrypted_index_mac = None
        self.tweak = None
        self.encrypted_index = None
        self.key_deriver = None

    def init_new(self):
        self.version = 1
        self.password_salt = KeyDeriver.new_salt()
        self.master_key = None
        self.master_key_hash = None
        self.encrypted_index_mac = None
        self.tweak = None
        self.encrypted_index = None
        self.key_deriver = KeyDeriver(16, 65536, 2)

    def exists(self):
        exists = os.path.isfile(self.path)

        if exists:
            log.debug(self, 'Index file exists ({})'.format(self.path))
        else:
            log.debug(self, 'Index file does not exist ({})'.format(self.path))

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

        log.verbose(self, 'Writing index to {}'.format(self.path))
        with open(self.path, 'wb') as f:
            f.write(data)
            f.flush()
        log.verbose(self, 'Finished writing index')

        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)

        log.debug(self, 'Saved Encrypted Index:')
        log.debug(self, '    Index Version:       {}'.format(self.version))
        log.debug(self, '    Password Salt:       {}'.format(log.format_bytes(self.password_salt)))
        log.debug(self, '    Master Key Hash:     {}'.format(log.format_bytes(self.master_key_hash)))
        log.debug(self, '    Encrypted Index MAC: {}'.format(log.format_bytes(self.encrypted_index_mac)))
        log.debug(self, '    Encrypted Index:     {}'.format(log.format_bytes(self.encrypted_index)))

    def load(self):
        data_buf = None

        log.verbose(self, 'Attempting to read index file at {}'.format(self.path))

        with open(self.path, 'rb') as f:
            data_buf = f.read()

        if len(data_buf) == 0:
            raise IndexCorruptException(self.path, 'Index is empty')


        buf = BytesIO(data_buf)

        self.version = int(buf.read(1)[0])

        if self.version == 1:
            self.load_version_1(buf, len(data_buf))
        else:
            raise UnknownIndexVersionException(self.path, self.version)

        log.debug(self, 'Loaded Encrypted Index:')
        log.debug(self, '    Index Version:       {}'.format(self.version))
        log.debug(self, '    Password Salt:       {}'.format(log.format_bytes(self.password_salt)))
        log.debug(self, '    Master Key Hash:     {}'.format(log.format_bytes(self.master_key_hash)))
        log.debug(self, '    Encrypted Index MAC: {}'.format(log.format_bytes(self.encrypted_index_mac)))
        log.debug(self, '    Encrypted Index:     {}'.format(log.format_bytes(self.encrypted_index)))

    def load_version_1(self, buf, total_length):
        if total_length < (1 + PASSWORD_SALT_LENGTH + MASTER_KEY_HASH_LENGTH + ENCRYPTED_INDEX_MAC_LENGTH + TWEAK_LENGTH + MIN_ENCRYPTED_INDEX_LENGTH):
            raise IndexCorruptException(self.path)

        buf.seek(1) # After version

        self.password_salt = buf.read(PASSWORD_SALT_LENGTH)
        self.master_key_hash = buf.read(MASTER_KEY_HASH_LENGTH)
        self.encrypted_index_mac = buf.read(ENCRYPTED_INDEX_MAC_LENGTH)
        self.tweak = buf.read(TWEAK_LENGTH)
        self.encrypted_index = buf.read()

        self.key_deriver = KeyDeriver(16, 65536, 2)

    def derive_master_key(self, password):
        # Don't store master key, as it could be incorrect
        return self.key_deriver.derive_master_key(password, self.password_salt)

    def verify_master_key(self, master_key):
        hasher = skein.skein1024()

        hasher.update(master_key)

        master_key_hash = hasher.digest()

        log.debug(self, 'Verify Master Key:')
        log.debug(self, '    Computed master key hash: {}'.format(log.format_bytes(master_key_hash)))
        log.debug(self, '    Stored master key hash:   {}'.format(log.format_bytes(self.master_key_hash)))

        return master_key_hash == self.master_key_hash

    def verify_index_integrity(self, master_key):
        signature_key = master_key[CIPHER_KEY_LENGTH : ]

        hasher = skein.skein1024(key=signature_key)

        hasher.update(self.tweak)
        hasher.update(self.encrypted_index)

        encrypted_index_mac = hasher.digest()

        log.debug(self, 'Verify Index Integrity:')
        log.debug(self, '    Computed index MAC: {}'.format(log.format_bytes(encrypted_index_mac)))
        log.debug(self, '    Stored index MAC:   {}'.format(log.format_bytes(self.encrypted_index_mac)))

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
