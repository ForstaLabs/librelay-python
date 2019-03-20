"""
Modular signal storage interface.
"""

import asyncio
import base64
import json
import logging
import os
import re
from . import backing
from libsignal.identitykey import IdentityKey
from libsignal.identitykeypair import IdentityKeyPair
from libsignal.invalidkeyidexception import InvalidKeyIdException
from libsignal.state.axolotlstore import AxolotlStore
from libsignal.state.prekeyrecord import PreKeyRecord
from libsignal.state.sessionrecord import SessionRecord
from libsignal.state.signedprekeyrecord import SignedPreKeyRecord

logger = logging.getLogger(__name__)
_store = None


class BackingStore(AxolotlStore):
    """ A modular store that supports pluggable backends like filesystem,
    databases. etc. """

    state_ns = 'state'
    session_ns = 'session'
    prekey_ns = 'prekey'
    signed_prekey_ns = 'signedprekey'
    identitykey_ns = 'identitykey'

    def __init__(self, backing=None, label=None):
        if label is None:
            label = os.environ.get('RELAY_STORAGE_LABEL', 'default')
        if backing is None:
            b = os.environ.get('RELAY_STORAGE_BACKING', 'fs')
            backing = self.getBackingClass(b)(label)
        self._backing = backing

    def initialize(self, *args, **kwargs):
        return self._backing.initialize(*args, **kwargs)

    def encode(self, obj):
        o = {}
        if isinstance(obj, bytes):
            o['encoding'] = 'bytes'
            o['data'] = base64.b64encode(obj).decode()
        else:
            o['data'] = obj
        return json.dumps(o)

    def decode(self, data):
        o = json.loads(data)
        encoding = o.get('encoding')
        if encoding == 'bytes':
            return base64.b64decode(o['data'])
        elif encoding:
            raise TypeError("Unsupported encoding: " + encoding)
        else:
            return o['data']

    def get(self, ns, key, default=None):
        try:
            data = self._backing.get(ns, str(key))
        except ReferenceError:
            return default
        else:
            return data and self.decode(data)

    def set(self, ns, key, value):
        return self._backing.set(ns, str(key), self.encode(value))

    def has(self, ns, key):
        return self._backing.has(ns, str(key))

    def remove(self, ns, key):
        return self._backing.remove(ns, str(key))

    def keys(self, ns, regex=None):
        return self._backing.keys(ns, regex=regex)

    def shutdown(self):
        return self._backing.shutdown()

    def getState(self, key, default=None):
        return self.get(self.state_ns, key, default)

    def putState(self, key, value):
        return self.set(self.state_ns, key, value)

    def removeState(self, key):
        return self.remove(self.state_ns, key)

    def getOurIdentity(self):
        serialized = self.getState('ourIdentityKey')
        return IdentityKeyPair(serialized=serialized)
    getIdentityKeyPair = getOurIdentity

    def saveOurIdentity(self, keypair):
        assert isinstance(keypair, IdentityKeyPair)
        self.putState('ourIdentityKey', keypair.serialize())

    def removeOurIdentity(self):
        self.removeState('ourIdentityKey')

    def getOurRegistrationId(self):
        return self.getState('registrationId')
    getLocalRegistrationId = getOurRegistrationId

    def loadPreKey(self, keyId):
        if not self.has(self.prekey_ns, keyId):
            raise InvalidKeyIdException(keyId)
        serialized = self.get(self.prekey_ns, keyId)
        return PreKeyRecord(serialized=serialized)

    def storePreKey(self, keyId, record):
        assert isinstance(record, PreKeyRecord)
        self.set(self.prekey_ns, keyId, record.serialize())

    def removePreKey(self, keyId):
        try:
            self.remove(self.prekey_ns, keyId)
        finally:
            # Avoid circular import..
            from .. import hub
            signal = hub.SignalClient.factory()
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(signal.refreshPreKeys())
            else:
                loop.run_until_complete(signal.refreshPreKeys())

    def loadSignedPreKey(self, keyId):
        serialized = self.get(self.signed_prekey_ns, keyId)
        if serialized is None:
            raise InvalidKeyIdException(keyId)
        return SignedPreKeyRecord(serialized=serialized)

    def storeSignedPreKey(self, keyId, record):
        assert isinstance(record, SignedPreKeyRecord)
        self.set(self.signed_prekey_ns, keyId, record.serialize())

    def removeSignedPreKey(self, keyId):
        self.remove(self.signed_prekey_ns, keyId)

    def loadSession(self, addr, deviceId):
        assert '.' not in addr
        serialized = self.get(self.session_ns, f'{addr}.{deviceId}')
        if serialized:
            return SessionRecord(serialized=serialized)
        else:
            return SessionRecord()

    def storeSession(self, addr, deviceId, record):
        assert '.' not in addr
        self.set(self.session_ns, f'{addr}.{deviceId}', record.serialize())

    def deleteSession(self, addr, deviceId):
        assert '.' not in addr
        self.remove(self.session_ns, f'{addr}.{deviceId}')

    def containsSession(self, addr, deviceId):
        return self.has(self.session_ns, f'{addr}.{deviceId}')

    def deleteAllSessions(self, addr):
        assert '.' not in addr
        for x in self.keys(self.session_ns, re.compile(addr + r'\..*')):
            self.remove(self.session_ns, x)

    def clearSessionStore(self):
        for x in self.keys(self.session_ns):
            self.remove(self.session_ns, x)

    def isTrustedIdentity(self, addr, remoteIdentityKey):
        assert '.' not in addr
        localIdentityKey = self.loadIdentity(addr)
        if not localIdentityKey:
            logger.warn("WARNING: Implicit trust of peer: %s" % addr)
            return True
        return localIdentityKey == remoteIdentityKey

    def loadIdentity(self, addr):
        assert '.' not in addr
        serialized = self.get(self.identitykey_ns, addr)
        if serialized:
            return IdentityKey(serialized, offset=0)

    def saveIdentity(self, addr, identKey):
        """ Returns True if the key was updated. """
        assert isinstance(identKey, IdentityKey)
        assert '.' not in addr
        existing = self.get(self.identitykey_ns, addr)
        raw = identKey.serialize()
        self.set(self.identitykey_ns, addr, raw)
        return not not (existing and not existing != raw)

    def removeIdentity(self, addr):
        assert '.' not in addr
        self.remove(self.identitykey_ns, addr)
        self.deleteAllSessions(addr)

    def getDeviceIds(self, addr):
        idents = self.keys(self.session_ns, re.compile(addr + r'\..*'))
        return [int(x.split('.')[1]) for x in idents]

    def getBackingClass(self, name):
        return {
            #"redis": backing.RedisBacking,
            #"postgres": backing.PostgresBacking,
            "fs": backing.FSBacking
        }[name]


def getStore():
    global _store
    if _store is None:
        _store = BackingStore()
        _store.initialize()
    return _store


def setStore(store):
    global _store
    _store = store
