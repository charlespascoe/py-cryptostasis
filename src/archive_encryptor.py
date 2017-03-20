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
        log.verbose(self, 'Generating new archive ID...')
        archive_id = self.archive_index.new_id()

        log.verbose(self, 'Generating encryption key and tweak for new archive...')
        key = os.urandom(consts.ENCRYPTION_KEY_LENGTH)
        tweak = os.urandom(consts.TWEAK_LENGTH)

        log.verbose(self, 'Writing new archive metadata...')
        output_strm.write(bytes([consts.ARCHIVE_VERSION]))
        output_strm.write(archive_id)

        cipher = Cipher(key, tweak)
        hasher = skein.skein1024()

        blocks_processed = 0

        block = bytes([])
        encrypted_block = bytes([])

        while True:
            block = input_strm.read(cipher.block_size_bytes)

            if len(block) != cipher.block_size_bytes:
                break

            encrypted_block = cipher.encrypt_block(block)
            hasher.update(encrypted_block)
            output_strm.write(encrypted_block)

            blocks_processed += 1

        encrypted_block = cipher.encrypt_block(cipher.append_padding(block))
        hasher.update(encrypted_block)
        output_strm.write(encrypted_block)
        output_strm.flush()

        blocks_processed += 1

        log.debug(self, 'Encrypt archive - blocks processed: {}'.format(blocks_processed))

        self.archive_index.add_entry(archive_id, name, key, tweak, hasher.digest())
        self.archive_index.save()

    def decrypt_archive(self, input_strm, output_strm):
        log.verbose(self, 'Attempting to decrypt archive')
        version_buf = input_strm.read(1)

        if len(version_buf) == 0:
            raise EncryptedArchiveCorruptException('Missing version')

        version = version_buf[0]

        log.debug(self, 'Archive Version: {}'.format(version))

        if version != 1:
            raise UnknownVersionException(version)

        archive_id = input_strm.read(consts.ARCHIVE_ID_LENGTH)

        if len(archive_id) != consts.ARCHIVE_ID_LENGTH:
            raise EncryptedArchiveCorruptException('Invalid archive ID')

        log.debug(self, 'Archive ID: {}'.format(log.format_bytes(archive_id)))

        archive_entry = self.archive_index.get_archive_entry(archive_id)

        if archive_entry is None:
            log.version(self, 'Archive not found')
            return None

        log.debug(self, 'Archive Entry:\n' + str(archive_entry))

        cipher = Cipher(archive_entry.key, archive_entry.tweak)
        hasher = skein.skein1024()

        encrypted_block = bytes([])
        next_encrypted_block = input_strm.read(cipher.block_size_bytes)
        block = bytes([])

        blocks_processed = 0

        while len(next_encrypted_block) > 0:
            encrypted_block = next_encrypted_block
            next_encrypted_block = input_strm.read(cipher.block_size_bytes)

            hasher.update(encrypted_block)

            if len(encrypted_block) != cipher.block_size_bytes:
                raise EncryptedArchiveCorruptException('Invalid ciphertext length')

            block = cipher.decrypt_block(encrypted_block)

            blocks_processed += 1

            if len(next_encrypted_block) == 0:
                # Last block - verify hash before removing padding
                file_hash = hasher.digest()

                if archive_entry.file_hash != file_hash:
                    raise EncryptedArchiveCorruptException('Encrypted file hash does not match')

                block = cipher.remove_padding(block)

            output_strm.write(block)

        log.debug(self, 'Decrypt archive - blocks processed: {}'.format(blocks_processed))

        return archive_entry
