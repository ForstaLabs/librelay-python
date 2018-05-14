import os
import datetime


class Attachment(object):

    def __init__(self, buf=None, name='Attachment', content_type=None, mtime=None):
        if type is None:
            content_type = 'application/octet-stream'
        if mtime is None:
            mtime = datetime.datetime.now()
        self.buf = buf
        self.name = name;
        self.content_type = content_type;
        self.mtime = mtime;

    @classmethod
    def from_file(cls, file_path, content_type=None):
        with open(file_path) as f:
            buf = f.read()
            stat = os.stat(f.fileno())
            name = f.name
        return cls(buf=buf, mtime=datetime.datetime.fromtimestamp(stat.st_mtime),
                   name=name, content_type=content_type)

    def get_meta(self):
        return {
            "name": self.name,
            "size": len(self.buf),
            "content_type": self.content_type,
            "mtime": self.mtime.isoformat()
        }
