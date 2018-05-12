
class StorageInterface {

    constructor(label) {
        this.label = label;
    }

    async initialize() {
    }

    async set(ns, key, value) {
        throw new Error("Not Implemented");
    }

    async get(ns, key) {
        /* If key not found should throw ReferenceError */
        throw new Error("Not Implemented");
    }

    async has(ns, key) {
        throw new Error("Not Implemented");
    }

    async remove(ns, key) {
        throw new Error("Not Implemented");
    }

    async keys(ns, regex) {
        throw new Error("Not Implemented");
    }

    async shutdown() {
    }
}

module.exports = StorageInterface;
