// vim: ts=4:sw=4:expandtab

const readline = require('readline');

function unencodeAddr(addr) {
    return addr.split(".");
}


const _maxTimeout = 0x7fffffff;  // `setTimeout` max valid value.
async function sleep(seconds) {
    let ms = seconds * 1000;
    while (ms > _maxTimeout) {
        // Support sleeping longer than the javascript max setTimeout...
        await new Promise(resolve => setTimeout(resolve, _maxTimeout));
        ms -= _maxTimeout;
    }
    return await new Promise(resolve => setTimeout(resolve, ms, seconds));
}


async function never() {
    return await new Promise(() => null);
}


async function consoleInput(prompt) {
    /* This simplifies authentication for a lot of use cases. */
    const rl = readline.createInterface(process.stdin, process.stdout);
    try { 
         return await new Promise(resolve => rl.question(prompt, resolve));
    } finally {
        rl.close();
    }   
}   


class RequestError extends Error {
    constructor(message, response, code, text, json) {
        super(message);
        this.name = 'RequestError';
        this.response = response;
        this.code = code;
        this.text = text;
        this.json = json;
    }
}


module.exports = {
    unencodeAddr,
    sleep,
    never,
    consoleInput,
    RequestError
};

