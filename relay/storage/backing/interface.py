class StorageInterface(object):
    """ ABC for storage subsystem. """

    def __init__(self, label):
        self.label = label

    async def initialize(self):
        pass

    async def set(self, ns, key, value):
        raise NotImplementedError("Required impl by subclass");

    async def get(self, ns, key):
        """ If key not found should throw ReferenceError """
        raise NotImplementedError("Required impl by subclass");

    async def has(self, ns, key):
        raise NotImplementedError("Not Implemented");
        raise NotImplementedError("Required impl by subclass");

    async def remove(self, ns, key):
        raise NotImplementedError("Required impl by subclass");

    async def keys(self, ns, regex):
        raise NotImplementedError("Required impl by subclass");

    async def shutdown(self):
        pass
