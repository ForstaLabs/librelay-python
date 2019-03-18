import asyncio
import relay
import logging
logging.basicConfig(level=0)

async def onMessage(ev):
    print("Got message", ev.data)

async def onSent(ev):
    print("Got SENT message", ev.data)

async def onKeyChange(ev):
    print("Got Keychange message", ev.key_error)
    ev.accept()


async def main():
    msgReceiver = relay.MessageReceiver.factory()
    msgReceiver.addEventListener('message', onMessage)
    msgReceiver.addEventListener('sent', onSent)
    msgReceiver.addEventListener('keychange', onKeyChange)
    await msgReceiver.connect()
    await msgReceiver.closed()

asyncio.get_event_loop().set_debug(True)
asyncio.get_event_loop().run_until_complete(main())
