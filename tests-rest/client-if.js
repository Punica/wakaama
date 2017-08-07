var client = {};

client.name = 'foobar';

client.connect = function (addr, callback) {
  callback(null, {});
};

module.exports = client;
