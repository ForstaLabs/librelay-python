librelay-python
========
Signal based Python library for end-to-end crypto with Forsta messaging platform.

[![Maturity](https://img.shields.io/pypi/status/librelay.svg)](https://pypi.python.org/pypi/librelay)
[![License](https://img.shields.io/pypi/l/librelay.svg)](https://pypi.python.org/pypi/librelay)
[![Change Log](https://img.shields.io/badge/change-log-blue.svg)](https://github.com/ForstaLabs/librelay-python/blob/master/CHANGELOG.md)
[![Version](https://img.shields.io/pypi/v/librelay.svg)](https://pypi.python.org/pypi/librelay)


About
--------
This is a Python library used to communicate with the Forsta messaging
platform.  The underlying protocol is based on the Signal end-to-end
crypto system.  The primary differences surround how provisioning is done
and the data payload, which is a custom JSON specification,
<https://goo.gl/eX7gyC>


Installation
--------
Ensure that you are using Python 3.6 or higher and simply install from GitHub:

    $ pip3 install librelay


Storage
--------
Librelay needs a backing store for holding crypto material.  The default
storage backing is `fs` which will store files in your local file-system
under `~/.librelay/storage`.

To support multiple instances of librelay on a single computer use
`relay.storage.setLabel('<something-unique>')` to shard your storage into
a unique namespace.


Provisioning
-------
PREREQUISITE: To use librelay you must first have a valid Forsta account.  You
can sign-up for free at <https://app.forsta.io/join>.  Once you have a valid
Forsta account you need to provision your librelay based application. 

With your Forsta account (e.g. `@myusername:myorgname`) you can get started
with the `registerAccount` function or the `registerDevice` function if adding
supplemental devices.

```python
import asyncio
import relay

async def main():
    userTag = input("Enter your login (e.g user:org): ")
    validator = await relay.AtlasClient.requestAuthenticationCode(userTag)
    await validator(input("SMS Verification Code: "))
    await relay.registerAccount();
    print("Successfully registered account")

asyncio.get_event_loop().run_until_complete(main())
```
Ref: <https://github.com/ForstaLabs/librelay-python/blob/master/examples/register.py>


Message Receiving
-------
Once your application is provisioned you can participate in the messaging
platform.   The simplest way to get familiar with the platform is to listen
for incoming messages and examine the content sent to your application in a
debugger.   Here is a very simple example of receiving messages.

```python
import asyncio
import relay

async def onMessage(ev):
    print("Got message", ev.data)


async def main():
    msgReceiver = relay.MessageReceiver.factory()
    msgReceiver.addEventListener('message', onMessage)
    await msgReceiver.connect()
    await msgReceiver.closed()

asyncio.get_event_loop().run_until_complete(main())
```
Ref: <https://github.com/ForstaLabs/librelay-python/blob/master/examples/recvmessage.py>


Message Sending
-------
```python
import asyncio
import relay


async def main():
    msgSender = relay.MessageSender.factory()
    to = input("To: ")  # Should be tag format. e.g @support:forsta.io
    text = input("Message: ")
    await msgSender.send(to=to, text=text)

asyncio.get_event_loop().run_until_complete(main())
```
Ref: <https://github.com/ForstaLabs/librelay-python/blob/master/examples/sendmessage.py>


Cryptography Notice
--------
This distribution includes cryptographic software. The country in which you
currently reside may have restrictions on the import, possession, use, and/or
re-export to another country, of encryption software.  BEFORE using any
encryption software, please check your country's laws, regulations and
policies concerning the import, possession, or use, and re-export of
encryption software, to see if this is permitted.  See
<https://www.wassenaar.org/> for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security
(BIS), has classified this software as Export Commodity Control Number (ECCN)
5D002.C.1, which includes information security software using or performing
cryptographic functions with asymmetric algorithms.  The form and manner of
this distribution makes it eligible for export under the License Exception ENC
Technology Software Unrestricted (TSU) exception (see the BIS Export
Administration Regulations, Section 740.13) for both object code and source code.


License
--------
Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

* Copyright 2014-2016 Open Whisper Systems
* Copyright 2017-2018 Forsta Inc.
