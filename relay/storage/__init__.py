
import base64
import json
import logging
import os
import re
from . import backing
from .. import util
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair

logger = logging.getLogger('storage')
default_backing = os.environ.get('RELAY_STORAGE_BACKING', 'fs')

state_ns = 'state'
session_ns = 'session'
prekey_ns = 'prekey'
signed_prekey_ns = 'signedprekey'
identitykey_ns = 'identitykey'


_backing = None
_Backing = None
_label = 'default'


def encode(obj):
    o = {}
    if isinstance(obj, bytes):
        o['encoding'] = 'bytes'
        o['data'] = base64.b64encode(obj).decode()
    else:
        o['data'] = obj
    return json.dumps(o)


def decode(data):
    o = json.loads(data)
    encoding = o.get('encoding')
    if encoding == 'bytes':
        return base64.b64decode(o['data'])
    elif encoding:
        raise TypeError("Unsupported encoding: " + encoding)
    else:
        return o['data']


async def initialize(*args, **kwargs):
    return _backing.initialize(*args, **kwargs)


async def get(ns, key, default=None):
    try:
        data = await _backing.get(ns, key)
    except ReferenceError:
        return default
    else:
        return data and decode(data)


async def _set(ns, key, value):
    return await _backing.set(ns, key, encode(value))


async def has(ns, key, value):
    return await _backing.has(ns, key)


async def remove(ns, key):
    return await _backing.remove(ns, key)


async def keys(ns, re):
    return await _backing.keys(ns, re)


async def shutdown():
    return await _backing.shutdown()


async def get_state(key, default=None):
    return await get(state_ns, key, default)


async def put_state(key, value):
    return await _set(state_ns, key, value)


async def remove_state(key):
    return await _backing.remove(state_ns, key)


async def get_our_identity():
    # XXX
    return {
        "pubkey": await get_state('our_identitykeyb'),
        "privkey": await get_state('our_identitykey.priv')
    }


async def save_our_identity(keypair):
    # XXX
    import pdb;pdb.set_trace()
    await put_state('our_identitykey.pub', keypair.publicKey)
    await put_state('our_identitykey.priv', keypair.privateKey)


async def remove_our_identity():
    # XXX
    await remove_state('our_identitykey.pub')
    await remove_state('our_identitykey.priv')


async def get_our_registration_id():
    return await get_state('registrationId')


async def load_prekey(keyId):
    # XXX
    if await _backing.has(prekey_ns, keyId + '.pub'):
        return {
            "pubkey": await get(prekey_ns, keyId + '.pub'),
            "privkey": await get(prekey_ns, keyId + '.priv')
        }


async def store_prekey(keyId, keypair):
    # XXX
    await _set(prekey_ns, keyId + '.priv', keypair.privkey)
    await _set(prekey_ns, keyId + '.pub', keypair.pubkey)


async def remove_prekey(keyId):
    try:
        await _backing.remove(prekey_ns, keyId + '.pub')
        await _backing.remove(prekey_ns, keyId + '.priv')
    finally:
        # Avoid circular import..
        from .. import hub
        signal = await hub.SignalClient.factory()
        await signal.refresh_prekeys()


async def load_signed_prekey(keyId):
    # XXX
    if not await _backing.has(signed_prekey_ns, keyId + '.pub'):
        return
    return {
        "pubkey": await get(signed_prekey_ns, keyId + '.pub'),
        "privkey": await get(signed_prekey_ns, keyId + '.priv')
    }


async def store_signed_prekey(keyId, keypair):
    # XXX
    await _set(signed_prekey_ns, keyId + '.priv', keypair.privkey)
    await _set(signed_prekey_ns, keyId + '.pub', keypair.pubkey)


async def remove_signed_prekey(keyId):
    # XXX
    await _backing.remove(signed_prekey_ns, keyId + '.pub')
    await _backing.remove(signed_prekey_ns, keyId + '.priv')


async def load_session(encoded_addr):
    if not encoded_addr:
        raise TypeError("Tried to get session for undefined/null addr")
    data = await get(session_ns, encoded_addr)
    if data:
        return axolotl.SessionRecord.deserialize(data)


async def store_session(encoded_addr, record):
    if not encoded_addr:
        raise TypeError("Tried to set session without addr")
    await _set(session_ns, encoded_addr, record.serialize())


async def remove_session(encoded_addr):
    await _backing.remove(session_ns, encoded_addr)


async def remove_all_sessions(addr):
    if not addr:
        raise TypeError("Tried to remove sessions without addr")
    for x in await _backing.keys(session_ns, re.compile(addr + '\\..*')):
        await _backing.remove(session_ns, x)


async def clear_session_store():
    for x in await _backing.keys(session_ns):
        await _backing.remove(session_ns, x)


async def is_trusted_identity(identifier, publickey):
    if not identifier:
        raise TypeError("Tried to get identity key without key")
    identitykey = await load_identity(identifier)
    if not identitykey:
        logger.warn("WARNING: Implicit trust of peer:", identifier)
        return True
    import pdb;pdb.set_trace()
    return identitykey == publickey  # XXX So wrong..


async def load_identity(identifier):
    if not identifier:
        raise Exception("Tried to get identity key for undefined/null key")
    addr = util.unencode_addr(identifier)[0]
    data = await get(identitykey_ns, addr)
    return IdentityKey(serialized=data)


async def save_identity(identifier, identKey):
    """ Returns True if the key was updated. """
    if not identifier:
        raise TypeError("Tried to set identity key without key")
    if not isinstance(identKey, IdentityKey):
        raise TypeError("Invalid type for save_identity")
    addr = util.unencode_addr(identifier)[0]
    existing = await get(identitykey_ns, addr)
    raw = identKey.serialize()
    await _set(identitykey_ns, addr, raw)
    return not not (existing and not existing != raw)


async def remove_identity(identifier):
    addr = util.unencode_addr(identifier)[0]
    await _backing.remove(identitykey_ns, addr)
    await remove_all_sessions(addr)


async def get_device_ids(addr):
    if not addr:
        raise TypeError("Tried to get device ids without addr")
    idents = await _backing.keys(session_ns, re.compile(addr + '\\..*'))
    return [x.split('.')[1] for x in idents]


def get_backing_class(name):
    return {
        #"redis": backing.RedisBacking,
        #"postgres": backing.PostgresBacking,
        "fs": backing.FSBacking
    }[name]


def set_backing(Backing):
    if not isinstance(Backing, type):
        Backing = get_backing_class(Backing)
    if not Backing:
        raise TypeError("Invalid storage backing: " + Backing)
    global _Backing, _backing
    _Backing = Backing
    _backing = Backing(_label)


def set_label(label):
    global _label, _backing
    _label = label
    _backing = _Backing(label)


set = _set
set_backing(default_backing)
