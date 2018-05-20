import asyncio
import relay


async def main():
    msgSender = relay.MessageSender.factory()
    to = input("To: ")  # Should be tag format. e.g @support:forsta.io
    text = input("Message: ")
    await msgSender.send(to=to, text=text)

asyncio.get_event_loop().run_until_complete(main())
