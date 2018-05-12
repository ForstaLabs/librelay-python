const StorageInterface = require('./interface');
const process = require('process');
const redis = require('redis');
const unifyOptions = require('redis/lib/createClient');


/* A proper async redis client */
class AsyncRedisClient extends redis.RedisClient {

    static createClient(...args) {
        const options = unifyOptions.apply(null, args);
        return new this(options);
    }

    _async(func, ...args) {
        return new Promise((resolve, reject) => {
            try {
                args.push((err, reply) => {
                    if (err !== null) {
                        reject(err);
                    } else {
                        resolve(reply);
                    }
                });
                func.apply(this, args);
            } catch(e) {
                reject(e);
            }
        });
    }

    async get(ns, key) {
        return await this._async(super.hget, ns, key);
    }

    async set(ns, key, value) {
        return await this._async(super.hset, ns, key, value);
    }

    async keys(ns) {
        return await this._async(super.hkeys, ns);
    }

    async del(ns, key) {
        return await this._async(super.hdel, ns, key);
    }

    async exists(ns, key) {
        return await this._async(super.hexists, ns, key);
    }
}


class RedisBacking extends StorageInterface {

    constructor(label) {
        super(label);
        this.client = AsyncRedisClient.createClient(process.env.REDIS_URL);
    }

    async set(ns, key, value) {
        if (value === undefined) {
            throw new Error("Tried to store undefined");
        }
        await this.client.set(this.label + '-' + ns, key, value);
    }

    async get(ns, key) {
        if (await this.client.exists(this.label + '-' + ns, key)) {
            return await this.client.get(this.label + '-' + ns, key);
        } else {
            throw new ReferenceError(key);
        }
    }

    async has(ns, key) {
        return await this.client.exists(this.label + '-' + ns, key);
    }

    async remove(ns, key) {
        await this.client.del(this.label + '-' + ns, key);
    }

    async keys(ns, regex) {
        const keys = await this.client.keys(this.label + '-' + ns);
        return regex ? keys.filter(x => x.match(regex)) : keys;
    }

    async shutdown() {
        this.client.quit();
        this.client = null;
    }
}

module.exports = RedisBacking;
