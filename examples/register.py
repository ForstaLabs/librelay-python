import asyncio
import getpass
import logging
import relay

logging.basicConfig(level=logging.DEBUG)


async def main():
    #userTag = input("Enter your login (e.g user:org): ") or 'mayfield:forsta.io'
    #auth_type, validator = await relay.AtlasClient.requestAuthentication(userTag)
    #if auth_type == 'sms':
    #    await validator(input("SMS Verification Code: "))
    #elif auth_type == 'password':
    #    await validator(getpass.getpass("Password Verification: "))
    #await relay.registerAccount();
    reg = await relay.registerDevice();
    print("Started provision:", reg)
    await reg['done']
    print("Successfully registered account")

asyncio.get_event_loop().run_until_complete(main())
