
var rest = require('node-rest-client');
var express = require('express');
var parser = require('body-parser');

var client = new rest.Client();
var url = 'http://localhost:8888/'


var server = express();

server.use(parser.json());

server.put('/notification', function (req, resp) {
    console.log('Notification request', req.url);
    console.log('Content:', req.body["async-responses"]);
    resp.send();
});

server.listen(7777);

var args = {
    data: {
        "url" : "http://localhost:7777/notification?x=123",
        "headers" : {
            "Authorization" : "auth",
            "foo": "bar",
        }
    },
    headers: { "Content-Type": "application/json" }
};
client.put(url + '/notification/callback', args, function (data, response) {
    console.log('Response for callback:', response.statusCode, data);
});


var args = {
    data: "2,500,123",
    headers: { "Content-Type": "application/octet-stream" }
};
client.post(url + 'endpoints/foobar/2/2/2', args, function (data, response) {
    console.log('Response for exec:', response.statusCode, data);
});

