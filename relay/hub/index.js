// vim: ts=4:sw=4:expandtab

'use strict';

const registration = require('./registration');

module.exports = {
    AtlasClient: require('./atlas'),
    SignalClient: require('./signal'),
    registerAccount: registration.registerAccount,
    registerDevice: registration.registerDevice,
};
