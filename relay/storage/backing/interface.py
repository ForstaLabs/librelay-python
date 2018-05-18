class StorageInterface(object):
    """ ABC for storage subsystem. """

    def __init__(self, label):
        self.label = label

    def initialize(self):
        pass

    def set(self, ns, key, value):
        raise NotImplementedError("Required impl by subclass");

    def get(self, ns, key):
        """ If key not found should throw ReferenceError """
        raise NotImplementedError("Required impl by subclass");

    def has(self, ns, key):
        raise NotImplementedError("Not Implemented");
        raise NotImplementedError("Required impl by subclass");

    def remove(self, ns, key):
        raise NotImplementedError("Required impl by subclass");

    def keys(self, ns, regex=None):
        raise NotImplementedError("Required impl by subclass");

    def shutdown(self):
        pass
