const process = require('process');
const relay = require('..');


async function main() {
    const argv = process.argv;
    if (argv.length < 4) {
        console.error(`Usage: ${argv[0]} ${argv[1]} TO MESSAGE [THREADID]`);
        return process.exit(2);
    }

    const sender = await relay.MessageSender.factory();
    await sender.send({
        to: argv[2],
        text: argv[3],
        threadId: argv[4] || '00000000-1111-2222-3333-444444444444'
    });
}

main().catch(e => console.error(e));
