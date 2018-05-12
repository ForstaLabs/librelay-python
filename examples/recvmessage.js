const relay = require('..');

function onMessage(ev) {
    const message = ev.data;
    console.info("Got message", message);
}

async function main() {
    const msgReceiver = await relay.MessageReceiver.factory();
    msgReceiver.addEventListener('message', onMessage);
    await msgReceiver.connect();
}

main().catch(e => console.error(e));
