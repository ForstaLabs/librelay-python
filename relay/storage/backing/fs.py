import os
from . import interface
from pathlib import Path


class FSBacking(interface.StorageInterface):

    version = 2

    def __init__(self, label):
        super().__init__(label)
        self.root = Path(Path.home(), '.librelay/storage', label,
                         f'v{self.version}')

    def to_path(self, ns, key):
        return Path(self.root, ns, key)

    def set(self, ns, key, value):
        d = Path(self.root, ns)
        for _ in range(2):
            try:
                with open(Path(d, key), 'w') as f:
                    f.write(value)
            except FileNotFoundError:
                d.mkdir(parents=True)

    def get(self, ns, key):
        try:
            with open(self.to_path(ns, key)) as f:
                return f.read()
        except FileNotFoundError:
            raise ReferenceError(key)

    def has(self, ns, key):
        return self.to_path(ns, key).is_file()

    def remove(self, ns, key):
        try:
            self.to_path(ns, key).unlink()
        except FileNotFoundError:
            pass

    def keys(self, ns, regex=None):
        try:
            files = [x.name for x in os.scandir(Path(self.root, ns))]
        except FileNotFoundError:
            return []
        if regex:
            return [x for x in files if regex.match(x)]
        else:
            return files
