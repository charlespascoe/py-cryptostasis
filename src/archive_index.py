import json
import log
import consts
import os


class ArchiveEntry:
    def __init__(self, entry_id, name, key, tweak, file_hash):
        self.id = entry_id
        self.name = name
        self.key = key
        self.tweak = tweak
        self.file_hash = file_hash

    @staticmethod
    def create(data):
        entry_id = bytes.fromhex(data['id'])
        name = data['name']
        key = bytes.fromhex(data['key'])
        tweak = bytes.fromhex(data['tweak'])
        file_hash = bytes.fromhex(data['hash'])

        return ArchiveEntry(entry_id, name, key, tweak, file_hash)

    def serialise(self):
        return {
            'id': self.id.hex(),
            'name': self.name,
            'key': self.key.hex(),
            'tweak': self.tweak.hex(),
            'hash': self.file_hash.hex()
        }


class ArchiveIndex:
    def __init__(self, encrypted_archive_index, index_buf = None):
        self.encrypted_archive_index = encrypted_archive_index

        if index_buf is not None:
            json_index = index_buf.decode('utf-8')

            log.debug('JSON Index: {}'.format(json_index))

            parsed_index = json.loads(json_index)

            self.index = [ArchiveEntry.create(data) for data in parsed_index]
        else:
            self.index = []

    def save(self):
        json_index = json.dumps([entry.serialise() for entry in self.index])
        index_buf = bytes(json_index, 'utf-8')

        self.encrypted_archive_index.encrypt_index(index_buf)
        self.encrypted_archive_index.save()

    def name_exists(self, name):
        for entry in self.index:
            if entry.name == name:
                return True

        return False

    def get_archive_entry(self, archive_id):
        for entry in self.index:
            if entry.id == archive_id:
                return entry

        return None

    def new_id(self):
        new_id = os.urandom(consts.ARCHIVE_ID_LENGTH)

        while self.get_archive_entry(new_id) is not None:
            new_id = os.urandom(consts.ARCHIVE_ID_LENGTH)

        return new_id

    def add_entry(self, entry_id, name, key, tweak, file_hash):
        log.debug('Adding archive entry:')
        log.debug('    Entry ID: {}...'.format(entry_id.hex()[:16]))
        log.debug('    Name: {}'.format(name))
        log.debug('    Key: {}...'.format(key.hex()[:16]))
        log.debug('    Tweak: {}'.format(tweak.hex()))
        log.debug('    Encrypted File Hash: {}...'.format(file_hash.hex()[:16]))
        self.index.append(ArchiveEntry(entry_id, name, key, tweak, file_hash))
