
import logging
from . import storage

logger = logging.getLogger(__name__)


class Event(object):

    def __init__(self, name):
        self.name = name


class KeyChangeEvent(Event):

    def __init__(self, key_error):
        super().__init__('keychange')
        self.key_error = key_error

    async def accept(self):
        await storage.remove_identity(self.key_error.addr)
        await storage.save_identity(self.key_error.addr, self.key_error.identitykey)
        self.key_error.accepted = True


class EventTarget(object):
    """ Mixin class for adding eventing. """

    async def dispatchEvent(self, ev):
        if not isinstance(ev, Event):
            raise TypeError('Expects an event')
        if not hasattr(self, '_listeners') or ev.name not in self._listeners:
            return
        for callback in self._listeners[ev.name]:
            try:
                await callback(ev)
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
