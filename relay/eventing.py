
import inspect
import logging
from . import storage

store = storage.getStore()
logger = logging.getLogger(__name__)


class Event(object):

    def __init__(self, name):
        self.name = name


class KeyChangeEvent(Event):

    def __init__(self, key_error):
        super().__init__('keychange')
        self.accepted = False
        self.addr = self.key_error.name
        self.key_error = key_error

    def __str__(self):
        return f'<KeyChangeEvent: {self.addr}>'

    def accept(self):
        store.removeIdentity(self.addr)
        store.saveIdentity(self.addr, self.key_error.getIdentityKey())
        self.accepted = True


class EventTarget(object):
    """ Mixin class for adding eventing. """

    async def dispatchEvent(self, ev):
        if not isinstance(ev, Event):
            raise TypeError('Expects an event')
        if not hasattr(self, '_listeners') or ev.name not in self._listeners:
            return
        for callback in self._listeners[ev.name]:
            try:
                r = callback(ev)
                if inspect.isawaitable(r):
                    await r
            except Exception:
                logger.exception(f'Event Listener Exception [{ev.name}]:')

    def addEventListener(self, name, callback):
        if not hasattr(self, '_listeners'):
            self._listeners = {}
        if name not in self._listeners:
            self._listeners[name] = [callback]
        else:
            self._listeners[name].append(callback)

    def removeEventListener(self, name, callback):
        if name not in self._listeners:
            return
        self._listeners[name].remove(callback)
