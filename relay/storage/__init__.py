"""
Modular axolotl storage interface.
"""

import asyncio
import base64
import json
import logging
import os
import re
from . import backing
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.state.axolotlstore import AxolotlStore
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.state.sessionrecord import SessionRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord

logger = logging.getLogger(__name__)


class BackingStore(AxolotlStore):
    """ A modular store that supports pluggable backends like filesystem,
    databases. etc. """

    state_ns = 'state'
    session_ns = 'session'
    prekey_ns = 'prekey'
    signed_prekey_ns = 'signedprekey'
    identitykey_ns = 'identitykey'

    def __init__(self, backing=None, label='default'):
        if backing is None:
            b = os.environ.get('RELAY_STORAGE_BACKING', 'fs')
            backing = self.getBackingClass(b)(label)
        self._backing = backing

    async def initialize(self, *args, **kwargs):
        return await self._backing.initialize(*args, **kwargs)

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

    async def get(self, ns, key, default=None):
        try:
            data = await self._backing.get(ns, str(key))
        except ReferenceError:
            return default
        else:
            return data and self.decode(data)

    async def set(self, ns, key, value):
        return await self._backing.set(ns, str(key), self.encode(value))

    async def has(self, ns, key):
        return await self._backing.has(ns, str(key))

    async def remove(self, ns, key):
        return await self._backing.remove(ns, str(key))

    async def keys(self, ns, regex=None):
        return await self._backing.keys(ns, regex=regex)

    async def shutdown(self):
        return await self._backing.shutdown()

    async def getState(self, key, default=None):
        return await self.get(self.state_ns, key, default)

    async def putState(self, key, value):
        return await self.set(self.state_ns, key, value)

    async def removeState(self, key):
        return await self.remove(self.state_ns, key)

    async def getOurIdentity(self):
        serialized = await self.getState('ourIdentityKey')
        return IdentityKeyPair(serialized=serialized)

    async def saveOurIdentity(self, keypair):
        assert isinstance(keypair, IdentityKeyPair)
        await self.putState('ourIdentityKey', keypair.serialize())

    async def removeOurIdentity(self):
        await self.removeState('ourIdentityKey')

    async def getOurRegistrationId(self):
        return await self.getState('registrationId')

    async def loadPreKey(self, keyId):
        if not await self.has(self.prekey_ns, keyId):
            raise InvalidKeyIdException(keyId)
        serialized = await self.get(self.prekey_ns, keyId)
        return PreKeyRecord(serialized=serialized)

    async def storePreKey(self, keyId, record):
        assert isinstance(record, PreKeyRecord)
        await self.set(self.prekey_ns, keyId, record.serialize())

    async def removePreKey(self, keyId):
        try:
            await self.remove(self.prekey_ns, keyId)
        finally:
            # Avoid circular import..
            from .. import hub
            signal = await hub.SignalClient.factory()
            await signal.refreshPreKeys()

    async def loadSignedPreKey(self, keyId):
        serialized = await self.get(self.signed_prekey_ns, keyId)
        if serialized is None:
            raise InvalidKeyIdException(keyId)
        return SignedPreKeyRecord(serialized=serialized)

    async def storeSignedPreKey(self, keyId, record):
        assert isinstance(record, SignedPreKeyRecord)
        await self.set(self.signed_prekey_ns, keyId, record.serialize())

    async def removeSignedPreKey(self, keyId):
        await self.remove(self.signed_prekey_ns, keyId)

    async def loadSession(self, addr, deviceId):
        assert '.' not in addr
        serialized = await self.get(self.session_ns, f'{addr}.{deviceId}')
        if serialized:
            return SessionRecord(serizlized=serialized)
        else:
            return SessionRecord()

    async def storeSession(self, addr, deviceId, record):
        assert '.' not in addr
        await self.set(self.session_ns, f'{addr}.{deviceId}',
                       record.serialize())

    async def deleteSession(self, addr, deviceId):
        assert '.' not in addr
        await self.remove(self.session_ns, f'{addr}.{deviceId}')

    async def deleteAllSessions(self, addr):
        assert '.' not in addr
        for x in await self.keys(self.session_ns, re.compile(addr + r'\..*')):
            await self.remove(self.session_ns, x)

    async def clearSessionStore(self):
        for x in await self.keys(self.session_ns):
            await self.remove(self.session_ns, x)

    async def isTrustedIdentity(self, addr, remoteIdentityKey):
        assert '.' not in addr
        localIdentityKey = await self.loadIdentity(addr)
        if not localIdentityKey:
            logger.warn("WARNING: Implicit trust of peer: %s" % addr)
            return True
        return localIdentityKey == remoteIdentityKey

    async def loadIdentity(self, addr):
        assert '.' not in addr
        serialized = await self.get(self.identitykey_ns, addr)
        return IdentityKey(serialized=serialized)

    async def saveIdentity(self, addr, identKey):
        """ Returns True if the key was updated. """
        assert isinstance(identKey, IdentityKey)
        assert '.' not in addr
        existing = await self.get(self.identitykey_ns, addr)
        raw = identKey.serialize()
        await self.set(self.identitykey_ns, addr, raw)
        return not not (existing and not existing != raw)

    async def removeIdentity(self, addr):
        assert '.' not in addr
        await self.remove(self.identitykey_ns, addr)
        await self.deleteAllSessions(addr)

    async def getDeviceIds(self, addr):
        idents = await self.keys(self.session_ns, re.compile(addr + r'\..*'))
        return [x.split('.')[1] for x in idents]

    def getBackingClass(self, name):
        return {
            #"redis": backing.RedisBacking,
            #"postgres": backing.PostgresBacking,
            "fs": backing.FSBacking
        }[name]


_store = None

def getStore():
    global _store
    if _store is None:
        _store = BackingStore()
        asyncio.get_event_loop().run_until_complete(_store.initialize())
    return _store


def setStore(store):
    global _store
    _store = store
