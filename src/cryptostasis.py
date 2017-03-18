#!/usr/bin/python3
from argparse import ArgumentParser
from encrypted_archive_index import EncryptedArchiveIndex
import sys
from getpass import getpass
import key_derivation
import log
from archive_encryptor import ArchiveEncryptor, EncryptedArchiveCorruptException
import consts
import os


VERSION = '0.1.0'


def new_password(prompt, confirm_prompt='Confirm Password: '):

    while True:
        password = getpass(prompt)
        confirm_password = getpass(confirm_prompt)

        if password == confirm_password:
            break

        log.msg('Passwords do not match - please try again')
        log.msg()

    return password


def load_archive(path):
    eai = EncryptedArchiveIndex(path)

    if not eai.exists():
        log.info('Archive Index does not exist - going through first time setup')
        log.msg('===== First Time Setup =====')
        log.msg('You\'ll need to set a password used to encrypt the archive index')
        password = new_password('New Index Password: ')
        eai.password_salt = key_derivation.new_salt()
        master_key = key_derivation.derive_master_key(password, eai.password_salt)
        eai.update_master_key(master_key)
        archive_index = eai.create_new_index()
        archive_index.save()
        return archive_index
    else:
        log.info('Attempting to load archive index')
        try:
            eai.load()
            log.info('Successfully loaded archive index')
        except Exception as e:
            log.msg('Failed to load archive index')
            log.debug(str(e))
            sys.exit(1)

        password = getpass('Index Password: ')
        master_key = key_derivation.derive_master_key(password, eai.password_salt)

        if not eai.verify_master_key(master_key):
            log.msg('Incorrect password')
            sys.exit(1)

        if not eai.verify_index_integrity(master_key):
            log.msg('Index corrupt')
            sys.exit(1)

        return eai.decrypt_index(master_key)


def encrypt(archive_index, input_strm, output_strm, archive_name):
    if archive_index.name_exists(archive_name):
        log.msg('\'{}\' archive exists - quitting'.format(archive_name))
        sys.exit(1)

    arch_enc = ArchiveEncryptor(archive_index)
    arch_enc.encrypt_archive(input_strm, output_strm, archive_name)


def decrypt(archive_index, input_strm, output_strm):
    arch_enc = ArchiveEncryptor(archive_index)
    try:
        archive_entry = arch_enc.decrypt_archive(input_strm, output_strm)

        if archive_entry is not None:
            log.msg('Successfully decrypted \'{}\' archive'.format(archive_entry.name))
            return True
        else:
            log.msg('Could not find th decryption key for this archive - are you sure that it is an encrypted archive?')
            return False
    except Exception as e:
        log.msg('Something went wrong trying to decrypt the archive')
        log.debug('Decryption failed - stack trace:\n{}'.format(str(e)))
        return False
    except EncryptedArchiveCorruptException as e:
        log.msg('Failed to decrypt archive: {}'.format(e.message))

        if e is EncryptedArchiveCorruptException:
            log.info('Corrupt archive - {}'.format(e.reason))

        log.debug('Full exception:\n{}'.format(str(e)))

        return False


def change_password(archive_index):
    new_pass = new_password('Enter the new index password: ')

    archive_index.encrypted_archive_index.password_salt = key_derivation.new_salt()
    master_key = key_derivation.derive_master_key(new_pass, archive_index.encrypted_archive_index.password_salt)
    archive_index.encrypted_archive_index.update_master_key(master_key)
    archive_index.save()
    log.msg('Successfully changed index password')


if __name__ == '__main__':
    parser = ArgumentParser()
    actions = parser.add_mutually_exclusive_group()

    parser.add_argument('-v', '--verbose', action='count', default=0, dest='verbosity')

    actions.add_argument('-e', '--encrypt', dest='archive_name', help='Encrypt archive (archive name must be unique)')
    actions.add_argument('-d', '--decrypt', dest='decrypt', help='Decrypt archive', action='store_true')
    actions.add_argument('-V', '--version', dest='version', help='Show version and quit', action='store_true')
    actions.add_argument('-l', '--list', dest='list', help='List all archive index entries', action='store_true')
    actions.add_argument('-c', '--change-password', dest='change_password', help='Change the index password', action='store_true')

    parser.add_argument('-f', '--input-file', type=str, dest='input_file', help='Input Archive File')
    parser.add_argument('-o', '--output-file', type=str, dest='output_file', help='Output File name')
    parser.add_argument(
        '-I',
        '--index',
        type=str,
        dest='index_file',
        default=consts.ARCHIVE_INDEX_DEFAULT_LOCATION,
        help='Archive Index File (defaults to {})'.format(consts.ARCHIVE_INDEX_DEFAULT_LOCATION)
    )

    args = parser.parse_args()

    if args.version:
        log.msg('Cryptostasis v{}'.format(VERSION))
        sys.exit(0)

    log.level = args.verbosity
    log.info('Verbosity level: {}'.format(args.verbosity))

    input_strm = sys.stdin.buffer
    output_strm = sys.stdout.buffer

    if args.input_file != None:
        input_strm = open(args.input_file, 'rb')

    if args.output_file != None:
        output_strm = open(args.output_file, 'wb')

    archive_index = load_archive(args.index_file)

    if args.archive_name != None:
        encrypt(archive_index, input_strm, output_strm, args.archive_name)
    elif args.decrypt:
        success = decrypt(archive_index, input_strm, output_strm)

        if not success:
            input_strm.close()
            output_strm.flush()
            output_strm.close()
            if args.output_file != None:
                os.remove(args.output_file)

            sys.exit(1)
    elif args.list:
        log.msg(str(archive_index))
    elif args.change_password:
        change_password(archive_index)
    else:
        parser.print_help()

    input_strm.close()
    output_strm.flush()
    output_strm.close()
