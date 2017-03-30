import os
import sys
import argon2
import consts
import log


class KeyDeriver:
    def __init__(self, time_cost, memory_cost, parallelism):
        if 0 >= time_cost or time_cost > 2**16:
            log.msg('Invalid time_cost value: {}'.format(time_cost))
            sys.exit(1)

        if 0 >= parallelism or parallelism > 64:
            log.msg('Invalid parallelism value: {}'.format(time_cost))
            sys.exit(1)

        if 8 * parallelism > memory_cost or memory_cost > 2**32:
            log.msg('Invalid memory_cost value: {} (minimum: 8 * parallelism = {}, maximum: {})'.format(time_cost, 8 * parallelism, 2**32))
            sys.exit(1)

        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.type = argon2.low_level.Type.I

    @staticmethod
    def new_salt():
        log.debug('KeyDeriver', 'Generating new salt')
        salt = os.urandom(consts.PASSWORD_SALT_LENGTH)
        log.debug('KeyDeriver', 'Generated new salt: {}'.format(salt.hex()))
        return salt

    def derive_master_key(self, password, salt):
        if isinstance(password, str):
            password = password.encode('utf-16')

        log.info(self, 'Deriving key, please wait... ')

        master_key = argon2.low_level.hash_secret_raw(
            secret = password,
            salt = salt,
            time_cost = self.time_cost,
            memory_cost = self.memory_cost,
            parallelism = self.parallelism,
            hash_len = consts.MASTER_KEY_LENGTH,
            type = self.type
        )

        log.info(self, 'Derived key!')

        return master_key
