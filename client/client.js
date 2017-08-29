var coap = require('coap');

var server = coap.createServer({type: 'udp6'});
const rport = 5555;
const UPDATE_PERIOD = 7500;
const OBSERVE_PERIOD = 3000;

server.on('request', function reqHandler(req, resp) {
    console.log('Received request:', req.code, req.url.toString());
    var path = req.url.toString();

    if (path == '/3303/0/5700') {
        if (req.code == '0.01') {  // GET
            var observe = req.headers['Observe'];

            if (observe === 0) {
                var interval = setInterval(function () {
                    resp.write(Math.random().toString());
                }, OBSERVE_PERIOD);
                resp.write(Math.random().toString());
            } else {
                resp.end(Math.random().toString());
            }
        } else {
            resp.code = '4.05'; // Method not allowed
            resp.end();
        }
    } else if (path == '/1/1') {
        if (req.code == '0.01') { // GET
            resp.end('Foobar');
        } else if (req.code == '0.02') { // POST
            var payload = req.payload.toString();
            console.log('Write foobar:', payload);
            resp.end();
        } else {
            resp.code = '4.05';
            resp.end();
        }
    } else if (path == '/2/2/2') {
        if (req.code == '0.02') { // POST
            console.log('Execute f(' + req.payload.toString() + ')');
            resp.end();
        } else {
            resp.code = '4.05';
            resp.end();
        }
    } else {
        resp.code = '4.04';
        resp.end();
    }
});

server.listen(5699, function() {
    console.log('Server started');
    server.agent = new coap.Agent({socket: server._sock, type: 'udp6'});
    clientRegister(server.agent);
});


function clientRegister(agent) {
    var name = 'foobar';
    var reg = coap.request({
        agent: agent,
        host: '::1',
        port: rport,
        method: 'POST',
        pathname: 'rd',
        query: 'ep=' + name + '&lt=120&lwm2m=1.0&b=UQ',
    });
    reg.end("</3303/0>");

    reg.on('response', function(res) {
        var updatePath = '/rd/' + res.headers['Location-Path'];
        console.log('Registered as ', updatePath);
        setInterval(function () { sendUpdate(agent, updatePath); }, UPDATE_PERIOD);
    });
}

function sendUpdate(agent, path) {
    var update = coap.request({
        agent: agent,
        host: '::1',
        port: rport,
        method: 'POST',
        pathname: path
    });
    update.end();
}


