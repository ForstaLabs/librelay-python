const relay = require('..');

async function main(secondary) {
    const userTag = await relay.util.consoleInput("Enter your login (e.g user:org): ");
    const validator = await relay.AtlasClient.requestAuthenticationCode(userTag);
    await validator(await relay.util.consoleInput("SMS Verification Code: "));
    if (secondary) {
        const registration = await relay.registerDevice();
        console.info("Awaiting auto-registration response...");
        await registration.done;
        console.info("Successfully registered new device");
    } else {
        await relay.registerAccount();
        console.info("Successfully registered account");
    }
}

main(true).catch(e => console.error(e));
