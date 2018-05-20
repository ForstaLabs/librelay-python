import asyncio
import relay

async def main():
    userTag = input("Enter your login (e.g user:org): ")
    validator = await relay.AtlasClient.requestAuthenticationCode(userTag)
    await validator(input("SMS Verification Code: "))
    await relay.registerAccount();
    print("Successfully registered account")

asyncio.get_event_loop().run_until_complete(main())
