#!/usr/bin/env python3
from argparse import ArgumentParser
from encrypted_archive_index import EncryptedArchiveIndex
import sys
from getpass import getpass
from key_deriver import KeyDeriver
import log
from archive_encryptor import ArchiveEncryptor, EncryptedArchiveCorruptException
import consts
import os


def new_password(prompt, confirm_prompt='Confirm Password: '):

    while True:
        password = getpass(prompt)
        confirm_password = getpass(confirm_prompt)

        if password == confirm_password:
            break

        log.msg('Passwords do not match - please try again')
        log.msg()

    return password


def load_archive_index(path):
    eai = EncryptedArchiveIndex(path)

    if not eai.exists():
        log.info('cryptostasis', 'Archive Index does not exist - going through first time setup')
        log.msg('===== First Time Setup =====')
        log.msg('You\'ll need to set a password used to encrypt the archive index')
        password = new_password('New Index Password: ')
        eai.init_new()
        master_key = eai.derive_master_key(password)
        eai.update_master_key(master_key)
        archive_index = eai.create_new_index()
        archive_index.save()
        return archive_index
    else:
        log.info('cryptostasis', 'Attempting to load archive index')
        try:
            eai.load()
            log.info('cryptostasis', 'Successfully loaded archive index')
        except Exception as e:
            log.msg('Failed to load archive index')
            log.debug('cryptostasis', str(e))
            sys.exit(1)

        password = getpass('Index Password: ')
        master_key = eai.derive_master_key(password)

        if not eai.verify_master_key(master_key):
            log.msg('Incorrect password')
            sys.exit(1)

        if not eai.verify_index_integrity(master_key):
            log.msg('Index corrupt')
            sys.exit(1)

        return eai.decrypt_index(master_key)


def get_input_strm(args):
    if args.input_file is not None:
        return open(args.input_file, 'rb')

    return sys.stdin.buffer


def get_output_strm(args):
    if args.output_file is not None:
        return open(args.output_file, 'wb')

    return sys.stdout.buffer

# Actions

def encrypt_archive(archive_index, args):
    input_strm = get_input_strm(args)
    output_strm = get_output_strm(args)

    archive_name = args.archive_name
    if archive_index.name_exists(archive_name):
        log.msg('\'{}\' archive exists - quitting'.format(archive_name))
        sys.exit(1)

    arch_enc = ArchiveEncryptor(archive_index)
    arch_enc.encrypt_archive(input_strm, output_strm, archive_name)

    input_strm.close()
    output_strm.flush()
    output_strm.close()


def decrypt_archive(archive_index, args):
    input_strm = get_input_strm(args)
    output_strm = get_output_strm(args)

    arch_enc = ArchiveEncryptor(archive_index)

    success = True

    try:
        archive_entry = arch_enc.decrypt_archive(input_strm, output_strm)

        if archive_entry is not None:
            log.msg('Successfully decrypted \'{}\' archive'.format(archive_entry.name))
        else:
            log.msg('Could not find th decryption key for this archive - are you sure that it is an encrypted archive?')
            success = False
    except Exception as e:
        log.msg('Something went wrong trying to decrypt the archive')
        log.debug('cryptostasis', 'Decryption failed - stack trace:\n{}'.format(str(e)))
        success = False
    except EncryptedArchiveCorruptException as e:
        log.msg('Failed to decrypt archive: {}'.format(e.message))

        if e is EncryptedArchiveCorruptException:
            log.info('cryptostasis', 'Corrupt archive - {}'.format(e.reason))

        log.debug('cryptostasis', 'Full exception:\n{}'.format(str(e)))

        success = False

    input_strm.close()
    output_strm.flush()
    output_strm.close()

    if not success:
        if args.output_file is not None:
            os.remove(args.output_file)

        return 1


def list_index(archive_index, args):
    log.msg(str(archive_index))


def change_password(archive_index, args):
    new_pass = new_password('Enter the new index password: ')

    eai = archive_index.encrypted_archive_index

    eai.password_salt = KeyDeriver.new_salt()

    if args.time_cost is not None:
        eai.time_cost = args.time_cost

    if args.memory_cost is not None:
        eai.memory_cost = args.memory_cost

    if args.parallelism is not None:
        eai.parallelism = args.parallelism

    master_key = archive_index.encrypted_archive_index.derive_master_key(new_pass)
    archive_index.encrypted_archive_index.update_master_key(master_key)
    archive_index.save()
    log.msg('Successfully changed index password')


def main():
    parser = ArgumentParser()

    parser.add_argument('-v', '--verbose', action='count', default=0, dest='verbosity')
    parser.add_argument('-V', '--version', dest='version', help='Show version and exit', action='store_true')

    parser.add_argument('--log-file', type=str, dest='log_file', help='Path to log file (use with --verbose)')
    parser.add_argument(
        '-I',
        '--index',
        type=str,
        dest='index_file',
        default=consts.INDEX_DEFAULT_LOCATION,
        help='Archive Index File (defaults to {})'.format(consts.INDEX_DEFAULT_LOCATION)
    )

    actions = parser.add_subparsers()

    encrypt_subparser = actions.add_parser('encrypt', help='Encrypt an archive')
    encrypt_subparser.set_defaults(func=encrypt_archive)
    encrypt_subparser.add_argument('archive_name')
    encrypt_subparser.add_argument('-f', '--input-file', type=str, dest='input_file', help='Input archive file (defaults to STDIN)')
    encrypt_subparser.add_argument('-o', '--output-file', type=str, dest='output_file', help='Encrypted output archive file (defaults to STDOUT)')

    decrypt_subparser = actions.add_parser('decrypt', help='Decrypt an archive')
    decrypt_subparser.set_defaults(func=decrypt_archive)
    decrypt_subparser.add_argument('-f', '--input-file', type=str, dest='input_file', help='Input encrypted archive file (defaults to STDIN)')
    decrypt_subparser.add_argument('-o', '--output-file', type=str, dest='output_file', help='Output archive file (defaults to STDOUT)')

    list_subparser = actions.add_parser('list', help='List entries in the index')
    list_subparser.set_defaults(func=list_index)

    change_password_subparser = actions.add_parser(
        'passwd',
        description = (
            'When changing the encryption password, you can also configure the Key Derivation Function (KDF) parameters. ' +
            'If they are not set, they default to the current parameters as loaded from the index. ' +
            'When creating a new index, the parameters are time_cost = {}, memory_cost = {}, and parallelism = {}'
                .format(consts.DEFAULT_TIME_COST, consts.DEFAULT_MEMORY_COST, consts.DEFAULT_PARALLELISM)
        ),
        help = 'Change index password'
    )
    change_password_subparser.set_defaults(func=change_password)
    change_password_subparser.add_argument('-t', '--time-cost', type=int, dest='time_cost', help='The time cost parameter passed to the KDF')
    change_password_subparser.add_argument('-m', '--memory-cost', type=int, dest='memory_cost', help='The memory cost parameter passed to the KDF')
    change_password_subparser.add_argument('-p', '--parallelism', type=int, dest='parallelism', help='The parallelism parameter passed to the KDF')

    args = parser.parse_args()

    if args.version:
        log.msg('Cryptostasis v{}'.format(consts.VERSION))
        sys.exit(0)

    log.level = args.verbosity
    log.info('cryptostasis', 'Verbosity level: {}'.format(args.verbosity))

    if args.log_file is not None:
        log.msg('Writing logs to: {}'.format(args.log_file))
        log.log_strm = open(args.log_file, 'w')

    archive_index = load_archive_index(args.index_file)

    status_code = 0

    if 'func' in args:
        status_code = args.func(archive_index, args)
    else:
        parser.print_help()

    log.log_strm.flush()
    log.log_strm.close()

    if status_code is None:
        sys.exit(0)
    else:
        sys.exit(status_code)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Keyboard interrupt')
