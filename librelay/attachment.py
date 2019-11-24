import os
import datetime


class Attachment(object):

    def __init__(self, buffer=None, name='Attachment', type=None, mtime=None):
        if type is None:
            type = 'application/octet-stream'
        if mtime is None:
            mtime = datetime.datetime.now()
        self.buffer = buffer
        self.name = name
        self.type = type
        self.mtime = mtime

    @classmethod
    def fromFile(cls, filePath, type=None):
        with open(filePath, 'rb') as f:
            buf = f.read()
            stat = os.stat(f.fileno())
            name = f.name
        return cls(buf, mtime=datetime.datetime.fromtimestamp(stat.st_mtime),
                   name=name, type=type)

    def getMeta(self):
        return {
            "name": self.name,
            "size": len(self.buffer),
            "type": self.type,
            "mtime": self.mtime.isoformat()
        }
