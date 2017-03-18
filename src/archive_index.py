import json
import log
import consts
import os
from datetime import datetime


class ArchiveEntry:
    def __init__(self, entry_id, name, key, tweak, file_hash, timestamp):
        self.id = entry_id
        self.name = name
        self.key = key
        self.tweak = tweak
        self.file_hash = file_hash
        self.timestamp = timestamp

    @staticmethod
    def create(data):
        entry_id = bytes.fromhex(data['id'])
        name = data['name']
        key = bytes.fromhex(data['key'])
        tweak = bytes.fromhex(data['tweak'])
        file_hash = bytes.fromhex(data['hash'])
        timestamp = data['timestamp']

        return ArchiveEntry(entry_id, name, key, tweak, file_hash, timestamp)

    def serialise(self):
        return {
            'id': self.id.hex(),
            'name': self.name,
            'key': self.key.hex(),
            'tweak': self.tweak.hex(),
            'hash': self.file_hash.hex(),
            'timestamp': self.timestamp
        }

    def format(self, name_col_length):
        return '{}  {}'.format(self.name.ljust(name_col_length), datetime.utcfromtimestamp(self.timestamp).ctime())

    def __str__(self):
        output = ''

        output += '    Entry ID: {}\n'.format(log.format_bytes(self.id))
        output += '    Name: {}\n'.format(self.name)
        output += '    Key: {}\n'.format(log.format_bytes(self.key))
        output += '    Tweak: {}\n'.format(log.format_bytes(self.tweak))
        output += '    Encrypted File Hash: {}\n'.format(log.format_bytes(self.file_hash))
        output += '    Timestamp: {}'.format(datetime.utcfromtimestamp(self.timestamp).ctime())

        return output


class ArchiveIndex:
    def __init__(self, encrypted_archive_index, index_buf = None):
        self.encrypted_archive_index = encrypted_archive_index

        if index_buf is not None:
            json_index = index_buf.decode('utf-8')

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
        entry = ArchiveEntry(entry_id, name, key, tweak, file_hash, round(datetime.utcnow().timestamp()))
        log.debug(self, 'Adding archive entry:')
        log.debug(self, str(entry))
        self.index.append(entry)

    def __str__(self):
        if len(self.index) == 0:
            return 'The index is empty'

        name_col_length = max([len(entry.name) for entry in self.index])

        lines = ['Name'.ljust(name_col_length) + '  Created']

        for entry in self.index:
            lines.append(entry.format(name_col_length))

        return '\n'.join(lines)
