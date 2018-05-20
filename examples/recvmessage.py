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
