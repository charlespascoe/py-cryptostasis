import skein
import consts
import log

class Cipher:
    @property
    def key_size_bytes(self):
        return 128

    @property
    def block_size_bytes(self):
        return self.key_size_bytes

    def __init__(self, key, tweak):
        self.threefish = skein.threefish(key, tweak)

    def encrypt(self, buf):
        out = bytes([])

        for i in range(0, len(buf) // self.block_size_bytes):
            out += self.encrypt_block(buf[self.block_size_bytes * i : self.block_size_bytes * (i + 1)])

        last_block_length = len(buf) % self.block_size_bytes

        if last_block_length == 0:
            padded_last_block = self.append_padding(bytes([]))
        else:
            padded_last_block = self.append_padding(buf[-last_block_length:])

        out += self.encrypt_block(padded_last_block)

        return out

    def decrypt(self, buf):
        if len(buf) % self.block_size_bytes != 0:
            raise Exception('Invalid ciphertext')

        out = bytes([])

        for i in range(0, len(buf) // self.block_size_bytes):
            out += self.decrypt_block(buf[self.block_size_bytes * i : self.block_size_bytes * (i + 1)])

        return self.remove_padding(out)

    def append_padding(self, block):
        padding_length = self.block_size_bytes - (len(block) % self.block_size_bytes)

        return block + bytes([padding_length] * padding_length)

    def remove_padding(self, block):
        padding_length = block[-1]

        if padding_length > len(block):
            raise Exception('Invalid padding')

        for pad_byte in block[-padding_length:]:
            if pad_byte != padding_length:
                raise Exception('Invalid padding')

        return block[:-padding_length]

    def encrypt_block(self, block):
        encrypted_block = self.threefish.encrypt_block(block)
        self.threefish.tweak = encrypted_block[ : consts.TWEAK_LENGTH]
        return encrypted_block

    def decrypt_block(self, encrypted_block):
        block = self.threefish.decrypt_block(encrypted_block)
        self.threefish.tweak = encrypted_block[ : consts.TWEAK_LENGTH]
        return block
