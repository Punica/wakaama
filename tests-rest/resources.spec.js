
const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const events = require('events');
var server = require('./server-if');
var client = require('./client-if');

chai.use(chai_http);

describe('Endpoints interface', function () {
  before(function (done) {
    var self = this;

    server.start();

    self.events = new events.EventEmitter();
    // TODO: swap interval with long-poll once server supports it
    setInterval(function () {
      chai.request(server)
        .get('/notification/pull')
        .end(function (err, res) {
          const responses = res.body['async-responses'];
          if (!responses)
            return;

          for (var i=0; i<responses.length; i++) {
            self.events.emit('async-response', responses[i]);
          }
        });
    }, 1000);

    client.connect(server.address(), function (err, res) {
      done();
    });
  });

  describe('GET /endpoints/{endpoint-name}/{resource-path}', function () {

    it('should return async-response-id and 202 code', function(done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .get('/endpoints/'+client.name+'/1/1')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('async-response-id');
          res.body['async-response-id'].should.be.a('string');
          res.body['async-response-id'].should.match(id_regex);

          done();
        });
    });

    it('should return 404 for invalid resource-path', function (done) {
      chai.request(server)
        .get('/endpoints/'+client.name+'/some/invalid/path')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 410 for non-existing endpoint', function (done) {
      chai.request(server)
        .get('/endpoints/non-existing-ep/1/1')
        .end(function (err, res) {
          res.should.have.status(410);
          done();
        });
    });

    it('should return 415 for unsupported content type', function (done) {
      chai.request(server)
        .get('/endpoints/'+client.name+'/1/1')
        .set('Accept', 'application/foobar')
        .end(function (err, res) {
          res.should.have.status(415);
          done();
        });
    });

    it('response should return 200 and valid payload', function (done) {
      var self = this;
      this.timeout(30000);

      chai.request(server)
        .get('/endpoints/'+client.name+'/1/1')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          self.events.on('async-response', resp => {
            if (resp.id == id) {
              resp.status.should.be.eql(200);
              // TODO: validate payload
              done();
            }
          });
        });
    });

    it('response should return 404 for invalid resource-path', function (done) {
      var self = this;
      this.timeout(30000);

      chai.request(server)
        .get('/endpoints/'+client.name+'/123/456/789')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          self.events.on('async-response', resp => {
            if (resp.id == id) {
              resp.status.should.be.eql(404);
              done();
            }
          });
        });
    });

  });

  describe('PUT /endpoints/{endpoint-name}/{resource}', function () {
    
  });

  describe('POST /endpoints/{endpoint-name}/{resource}', function () {
    
  });

});
