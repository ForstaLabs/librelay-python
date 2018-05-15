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

    async def set(self, ns, key, value):
        d = Path(self.root, ns)
        for _ in range(2):
            try:
                with open(Path(d, key), 'w') as f:
                    f.write(value)
            except FileNotFoundError:
                d.mkdir(parents=True)

    async def get(self, ns, key):
        try:
            with open(self.to_path(ns, key)) as f:
                return f.read()
        except FileNotFoundError:
            raise ReferenceError(key)

    async def has(self, ns, key):
        return self.to_path(ns, key).is_file()

    async def remove(self, ns, key):
        try:
            self.to_path(ns, key).unlink()
        except FileNotFoundError:
            pass

    async def keys(self, ns, regex=None):
        try:
            scanit = os.scandir(Path(self.root, ns))
        except FileNotFoundError:
            return []
        if regex:
            return [x for x in scanit if regex.match(x)]
        else:
            return list(scanit)
