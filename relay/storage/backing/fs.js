const StorageInterface = require('./interface');
const fs = require('fs');
const os = require('os');
const path = require('path');


async function mkdirp(dir, mode) {
    try {
        await new Promise((resolve, reject) => fs.mkdir(dir, mode, err => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        }));
    } catch(e) {
        if (e.code === 'ENOENT') {
            await mkdirp(path.dirname(dir), mode);
            await mkdirp(dir, mode);
        }
    }
}

async function fstat(path) {
    return await new Promise((resolve, reject) => fs.stat(path, (err, stats) => {
        if (err) {
            reject(err);
        } else {
            resolve(stats);
        }
    }));
}

async function is_file(path) {
    try {
        return (await fstat(path)).isFile();
    } catch(e) {
        return false;
    }
}

async function fwritefile(file, data) {
    return await new Promise((resolve, reject) => fs.writeFile(file, data, err => {
        if (err) {
            reject(err);
        } else {
            resolve();
        }
    }));
}

async function freadfile(file, data) {
    return await new Promise((resolve, reject) => fs.readFile(file, (err, data) => {
        if (err) {
            reject(err);
        } else {
            resolve(data);
        }
    }));
}

async function funlink(path) {
    return await new Promise((resolve, reject) => fs.unlink(path, err => {
        if (err) {
            reject(err);
        } else {
            resolve();
        }
    }));
}

async function freaddir(path) {
    return await new Promise((resolve, reject) => fs.readdir(path, (err, files) => {
        if (err) {
            reject(err);
        } else {
            resolve(files);
        }
    }));
}

class FSBacking extends StorageInterface {

    constructor(label) {
        super(label);
        const version = 1;
        this.root = path.join(os.homedir(), '.librelay/storage', label, 'v' + version);
    }

    async set(ns, key, value) {
        const dir = path.join(this.root, ns);
        for (let i = 0; i < 2; i++) {
            try {
                await fwritefile(path.join(dir, key), value);
                return;
            } catch(e) {
                if (e.code === 'ENOENT') {
                    await mkdirp(dir);
                } else {
                    throw e;
                }
            }
        }
    }

    async get(ns, key) {
        try {
            return await freadfile(path.join(this.root, ns, key));
        } catch(e) {
            if (e.code === 'ENOENT') {
                throw new ReferenceError(key);
            } else {
                throw e;
            }
        }
    }

    async has(ns, key) {
        return await is_file(path.join(this.root, ns, key));
    }

    async remove(ns, key) {
        try {
            await funlink(path.join(this.root, ns, key));
        } catch(e) {
            if (e.code !== 'ENOENT') {
                throw e;
            }
        }
    }

    async keys(ns, regex) {
        let keys;
        try {
            keys = await freaddir(path.join(this.root, ns));
        } catch(e) {
            if (e.code === 'ENOENT') {
                return [];
            }
        }
        return regex ? keys.filter(x => x.match(regex)) : keys;
    }
}

module.exports = FSBacking;
