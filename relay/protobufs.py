import protobufs
const protobuf = require('protobufjs');


const proto_files = [
    'IncomingPushMessageSignal.proto',
    'SubProtocol.proto',
    'DeviceMessages.proto'
];
const protodir = __dirname + '/../protos/';

for (const f of proto_files) {
    const p = protobuf.loadSync(protodir + f).lookup('relay');
    for (const message in p.nested) {
        exports[message] = p.lookup(message);
    }
}
