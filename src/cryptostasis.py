from argparse import ArgumentParser
from encrypted_archive_index import EncryptedArchiveIndex
import sys
from getpass import getpass
import key_derivation
import log
from archive_encryptor import ArchiveEncryptor
import consts


def print_stderr(message = '', line_end = '\n'):
    sys.stderr.write(message)
    sys.stderr.write(line_end)
    sys.stderr.flush()


def new_password():
    print_stderr('===== First Time Setup =====')
    print_stderr('You\'ll need to set a password used to encrypt the archive index')

    while True:
        password = getpass('New Index Password: ')
        confirm_password = getpass('Confirm Password: ')

        if password == confirm_password:
            break

        print_stderr('Passwords do not match - please try again')
        print_stderr()

    return password


def load_archive(path):
    eai = EncryptedArchiveIndex(path)

    if not eai.exists():
        log.info('Archive Index does not exist - going through first time setup')
        password = new_password()
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
            log.info('Failed to load archive index')
            print_stderr(str(e))
            sys.exit(1)

        password = getpass('Index Password: ')
        master_key = key_derivation.derive_master_key(password, eai.password_salt)

        if not eai.verify_master_key(master_key):
            print_stderr('Incorrect password')
            sys.exit(1)

        if not eai.verify_index_integrity(master_key):
            print_stderr('Index corrupt')
            sys.exit(1)

        return eai.decrypt_index(master_key)


def encrypt(archive_index, input_strm, output_strm, archive_name):
    if archive_index.name_exists(archive_name):
        print_stderr('\'{}\' archive exists - quitting'.format(archive_name))
        sys.exit(1)

    arch_enc = ArchiveEncryptor(archive_index)
    arch_enc.encrypt_archive(input_strm, output_strm, archive_name)


def decrypt(input_strm, output_strm):
    output_strm.write(input_strm.read(10))

if __name__ == '__main__':
    parser = ArgumentParser()
    actions = parser.add_mutually_exclusive_group()

    parser.add_argument('-v', '--verbose', action='count', default=0, dest='verbosity')

    actions.add_argument('-e', dest='archive_name', help='Encrypt archive (archive name must be unique)')
    actions.add_argument('-d', dest='decrypt', help='Decrypt archive', action='store_true')

    parser.add_argument('-f', type=str, dest='input_file', help='Input Archive File')
    parser.add_argument('-o', type=str, dest='output_file', help='Output File name')

    args = parser.parse_args()

    log.level = args.verbosity
    log.info('Verbosity level: {}'.format(args.verbosity))

    input_strm = sys.stdin.buffer
    output_strm = sys.stdout.buffer

    if args.input_file != None:
        input_strm = open(args.input_file, 'rb')

    if args.output_file != None:
        output_strm = open(args.output_file, 'wb')

    archive_index = load_archive('~/.cryptostasis/index')

    if args.archive_name != None:
        encrypt(archive_index, input_strm, output_strm, args.archive_name)
    elif args.decrypt:
        decrypt(input_strm, output_strm)
    else:
        parser.print_help()

    input_strm.close()
    output_strm.flush()
    output_strm.close()
