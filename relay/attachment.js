// vim: ts=4:sw=4:expandtab

'use strict';

const fs = require('fs');
const path = require('path');


class Attachment {

    constructor({
        buffer=null,
        name='Attachment',
        type='application/octet-stream',
        mtime=new Date()
    }) {
        this.buffer = buffer;
        this.name = name;
        this.type = type;
        this.mtime = mtime;
    }

    static fromFile(filePath, type) {
        const fStat = fs.statSync(filePath);
        const buffer = fs.readFileSync(filePath);
        return new this({
            buffer,
            mtime: fStat.mtime,
            name: path.basename(filePath),
            type
        });
    }

    getMeta() {
        return {
            name: this.name,
            size: this.buffer.size,
            type: this.type,
            mtime: this.mtime.toISOString(),
        };
    }
}

module.exports = Attachment;
