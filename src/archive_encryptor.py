import skein
import os
from cipher import Cipher
import consts
import log

class ArchiveEncryptorException(Exception):
    def __init__(self, message):
        super().__init__(message)

class EncryptedArchiveCorruptException(ArchiveEncryptorException):
    def __init__(self, reason):
        super().__init__('The encrypted archive is corrupt')
        self.reason = reason

class UnknownVersionException(ArchiveEncryptorException):
    def __init__(self, version):
        super().__init__('Unexpected archive version: {}'.format(version))
        self.version = version

class ArchiveEncryptor:
    def __init__(self, archive_index):
        self.archive_index = archive_index

    def encrypt_archive(self, input_strm, output_strm, name):
        log.verbose(self, 'Generating archive ID...')
        archive_id = self.archive_index.new_id()

        log.verbose(self, 'Generating encryption key and tweak...')
        key = os.urandom(consts.ENCRYPTION_KEY_LENGTH)
        tweak = os.urandom(consts.TWEAK_LENGTH)

        log.verbose(self, 'Writing archive metadata')
        output_strm.write(bytes([consts.ARCHIVE_VERSION]))
        output_strm.write(archive_id)

        cipher = Cipher(key, tweak)
        hasher = skein.skein1024()

        block = bytes([])
        encrypted_block = bytes([])

        while True:
            block = input_strm.read(cipher.block_size_bytes)

            if len(block) != cipher.block_size_bytes:
                break

            encrypted_block = cipher.encrypt_block(block)
            hasher.update(encrypted_block)
            output_strm.write(encrypted_block)

        encrypted_block = cipher.encrypt_block(cipher.append_padding(block))
        hasher.update(encrypted_block)
        output_strm.write(encrypted_block)
        output_strm.flush()

        self.archive_index.add_entry(archive_id, name, key, tweak, hasher.digest())
        self.archive_index.save()

    def decrypt_archive(self, input_strm, output_strm):
        version_buf = input_strm.read(1)

        if len(version_buf) == 0:
            raise EncryptedArchiveCorruptException('Missing version')

        version = version_buf[0]

        if version != 1:
            raise UnknownVersionException(version)

        archive_id = input_strm.read(consts.ARCHIVE_ID_LENGTH)

        if len(archive_id) != consts.ARCHIVE_ID_LENGTH:
            raise EncryptedArchiveCorruptException('Invalid archive ID')

        archive_entry = self.archive_index.get_archive_entry(archive_id)

        if archive_entry is None:
            return None

        cipher = Cipher(archive_entry.key, archive_entry.tweak)
        hasher = skein.skein1024()

        encrypted_block = bytes([])
        next_encrypted_block = input_strm.read(cipher.block_size_bytes)
        block = bytes([])

        while len(next_encrypted_block) > 0:
            encrypted_block = next_encrypted_block
            next_encrypted_block = input_strm.read(cipher.block_size_bytes)

            hasher.update(encrypted_block)

            if len(encrypted_block) != cipher.block_size_bytes:
                raise EncryptedArchiveCorruptException('Invalid ciphertext length')

            if len(next_encrypted_block) == 0:
                # Last block - verify hash before removing padding
                file_hash = hasher.digest()

                if archive_entry.file_hash != file_hash:
                    raise EncryptedArchiveCorruptException('Encrypted file hash does not match')

                block = cipher.remove_padding(cipher.decrypt_block(encrypted_block))
            else:
                block = cipher.decrypt_block(encrypted_block)

            output_strm.write(block)

        return archive_entry
