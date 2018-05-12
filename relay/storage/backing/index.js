module.exports = {
    RedisBacking: require('./redis'),
    FSBacking: require('./fs'),
    PostgresBacking: require('./postgres'),
    BackingInterface: require('./interface')
};
