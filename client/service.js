
var rest = require('node-rest-client');

var client = new rest.Client();
var url = 'http://localhost:8888/'


function client_paths_cb(data, response) {
    //var obj = JSON.parse(data);
    console.log('URIs:', data);
    for (var i=0; i<data.length; i++) {
        console.log('Reading:', data[i].uri);
    }
}

client.get(url+'endpoints/', function (data, response) {
    console.log('Client list:', data);
    //console.log(response);
    for (var ci=0; ci<data.length; ci++) {
        var ep = data[ci];
        console.log('Endpoint #' + ci + ':', ep);
        client.get(url+'endpoints/' + ep.name, function (uris, response) {
            console.log('URIs:', uris);
            for (var ui=0; ui<uris.length; ui++) {
                var uri = uris[ui].uri;
                console.log('Reading:', uri);
                client.get(url+'endpoints/' + ep.name + uri, function (data, response) {
                    console.log('Data:', JSON.stringify(data));
                });
            }
        });
    }
});

setTimeout(function() {
    client.get(url + 'endpoints/foobar/3303/0/5700', function (data, response) {
        console.log('Response for read:', response.statusCode, data);
    });
}, 5000);

setTimeout(function() {
    var args = {
        data: "foobar",
        headers: { "Content-Type": "application/octet-stream" }
    };
    client.put(url + 'endpoints/foobar/1/1', args, function (data, response) {
        console.log('Response for write:', response.statusCode, data);
    });
}, 6000);

setTimeout(function() {
    var args = {
        data: { test: "hello" },
        headers: { "Content-Type": "application/json" }
        //headers: { "Content-Type": "application/vnd.oma.lwm2m+json" }
    };

    client.put(url + 'endpoints/foobar/1/1', args, function (data, response) {
        console.log('Response for write:', response.statusCode, data);
    });
}, 7000);

setTimeout(function() {
    client.get(url + 'endpoints/foobaz/3303/0/5700', function (data, response) {
        console.log('Response for read:', response.statusCode, data);
    });
}, 8000);

setInterval(function() {
    client.get(url + "notification/pull", function (data, response) {
        console.log(data);
    });
}, 2000);

