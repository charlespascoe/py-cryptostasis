import json
import log


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
        name = bytes.fromhex(data['name'])
        key = bytes.fromhex(data['key'])
        tweak = bytes.fromhex(data['tweak'])
        file_hash = bytes.fromhex(data['hash'])

    def serialise(self):
        return {
            'id': self.entry_id.hex(),
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
