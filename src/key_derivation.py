import os
import argon2
import consts
import log


TIME_COST = 16
MEMORY_COST = 65536
PARALLELISM = 2
TYPE = argon2.low_level.Type.I


def new_salt():
    log.debug('Generating new salt')
    salt = os.urandom(consts.PASSWORD_SALT_LENGTH)
    log.debug('Generated new salt: {}'.format(salt.hex()))
    return salt


def derive_master_key(password, salt):
    log.info('Deriving key, please wait... ')

    master_key = argon2.low_level.hash_secret_raw(
        secret=bytes(password, 'utf-16'),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len = consts.MASTER_KEY_LENGTH,
        type=TYPE
    )

    log.info('Derived key!')

    return master_key
