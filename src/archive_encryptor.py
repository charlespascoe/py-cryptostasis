import skein
import os
from cipher import Cipher
import consts
import log


class ArchiveEncryptor:
    def __init__(self, archive_index):
        self.archive_index = archive_index

    def encrypt_archive(self, input_strm, output_strm, name):
        archive_id = self.archive_index.new_id()

        key = os.urandom(consts.ENCRYPTION_KEY_LENGTH)
        tweak = os.urandom(consts.TWEAK_LENGTH)

        output_strm.write(archive_id)

        cipher = Cipher(key, tweak)
        hasher = skein.skein1024()

        block = bytes([])
        encrypted_block = bytes([])

        while True:
            block = input_strm.read(cipher.block_size_bytes)

            if len(block) != cipher.block_size_bytes:
                break

            log.debug('Encrypt - Block length: {}'.format(len(block)))

            encrypted_block = cipher.encrypt_block(block)
            hasher.update(encrypt_block)
            output_strm.write(encrypted_block)

        log.debug('Encrypt - Last Block Length: {}'.format(len(block)))

        encrypted_block = cipher.encrypt_block(cipher.append_padding(block))
        hasher.update(encrypted_block)
        output_strm.write(encrypted_block)
        output_strm.flush()

        self.archive_index.add_entry(archive_id, name, key, tweak, hasher.digest())
        self.archive_index.save()
