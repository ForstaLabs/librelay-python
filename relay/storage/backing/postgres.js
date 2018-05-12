const StorageInterface = require('./interface');
const { Client } = require('pg');

class PostgresBacking extends StorageInterface {

    constructor(label) {
        super(label);
        this.tableName = 'faux_redis_' + this.label.toLowerCase().replace(/[^a-z0-9_]/g, '_');
        this.client = new Client({ connectionString: process.env.DATABASE_URL });
        this.queryCreateTableIfNeeded = `
            CREATE TABLE IF NOT EXISTS ${this.tableName} (
                namespace TEXT,
                key TEXT,
                value TEXT,
                PRIMARY KEY (namespace, key)
            );`;

        this.querySetValue = `
            INSERT INTO ${this.tableName} (namespace, key, value)
                VALUES ($1::text, $2::text, $3::text)
                ON CONFLICT (namespace, key)
                    DO UPDATE SET value=$3::text`;

        this.queryGetValue = `
            SELECT value FROM ${this.tableName} WHERE namespace=$1::text AND key=$2::text`;

        this.queryRemoveValue = `
            DELETE FROM ${this.tableName} WHERE namespace=$1::text AND key=$2::text`;

        this.queryGetKeys = `
            SELECT key FROM ${this.tableName} WHERE namespace=$1::text`;
    }

    async initialize() {
        await this.client.connect();
        return this.client.query(this.queryCreateTableIfNeeded);
    }

    async set(ns, key, value) {
        if (value === undefined) throw new Error("Tried to store undefined");
        const result = await this.client.query(this.querySetValue, [ns, key, value]);
        if (result.rowCount !== 1) throw new Error('Failure in postgres set');
    }

    async get(ns, key) {
        const result = await this.client.query(this.queryGetValue, [ns, key]);
        if (result.rowCount !== 1) throw new ReferenceError(key);
        return result.rows[0].value;
    }

    async has(ns, key) {
        const result = await this.client.query(this.queryGetValue, [ns, key]);
        return result.rowCount === 1;
    }

    async remove(ns, key) {
        const result = await this.client.query(this.queryRemoveValue, [ns, key]);
        return result.rowCount === 1;
    }

    async keys(ns, regex) {
        const result = await this.client.query(this.queryGetKeys, [ns]);
        const keys = result.rows.map(r => r.key);
        return regex ? keys.filter(x => x.match(regex)) : keys;
    }

    async shutdown() {
        await this.client.end();
        this.client = null;
    }
}

module.exports = PostgresBacking;
