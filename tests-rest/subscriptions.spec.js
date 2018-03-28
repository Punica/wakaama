
const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const events = require('events');
var server = require('./server-if');
var ClientInterface = require('./client-if');

chai.use(chai_http);

describe('Subscriptions interface', function () {
  const client = new ClientInterface();

  before(function (done) {
    var self = this;

    server.start();

    self.events = new events.EventEmitter();
    // TODO: swap interval with long-poll once server supports it
    self.interval = setInterval(function () {
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

    client.connect(server.address(), (err, res) => {
      done();
    });
  });

  after(function () {
    clearInterval(this.interval);
    client.disconnect();
  });

  describe('PUT /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return async-response-id and 202 code', function(done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
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

    it('should return 404 on invalid endpoint', function (done) {
      chai.request(server)
        .put('/subscriptions/non-existing/3303/0/5700')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 404 on invalid path', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/non/existing/path')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should not duplicate registrations', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          chai.request(server)
            .put('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(202);

              res.body['async-response-id'].should.be.eql(id);
              done();
            });
        });
    });

    it('should receive at least two async-responses', function(done) {
      // Check for at least two valid async-responses, that come separately
      var self = this;

      this.timeout(30000);

      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          var count = 0;
          var ts = 0;
          self.events.on('async-response', function (resp) {
            if (resp.id !== id) {
              return;
            }

            var dt = new Date().getTime() - ts;

            resp.should.have.status(200);
            dt.should.be.at.least(900);

            ts = new Date().getTime();
            count++;

            if (count == 2) { // wait for two responses
              done();
            }
          });

          //setTimeout(() => { client.temperature = -5.0; }, 123);
          setTimeout(() => { client.temperature = 21.0; }, 1234);
        });
    });
  });

  describe('DELETE /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return async-response-id and 204 code', function(done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          const id = res.body['async-response-id'];
          chai.request(server)
            .delete('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(204);

              done();
            });
        });
    });

    it('should return 404 on invalid endpoint', function (done) {
      chai.request(server)
        .delete('/subscriptions/non-existing/3303/0/5700')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 404 on invalid path', function (done) {
      chai.request(server)
        .delete('/subscriptions/' + client.name + '/non/existing/path')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });

    it('should return 404 on valid path', function (done) {
      chai.request(server)
        .delete('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          res.should.have.status(404);
          done();
        });
    });
  });

  describe('PUT DELETE PUT /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return async-response', function (done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          chai.request(server)
            .delete('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(204);

              const id = res.body['async-response-id'];
              chai.request(server)
                .put('/subscriptions/' + client.name + '/3303/0/5700')
                .end(function (err, res) {
                  should.not.exist(err);
                  res.should.have.header('content-type', 'application/json');

                  res.body.should.be.a('object');
                  res.body.should.have.property('async-response-id');
                  res.body['async-response-id'].should.be.a('string');
                  res.body['async-response-id'].should.match(id_regex);

                  done();
                });
            });
        });
    });
  });

  describe('PUT DELETE DELETE /subscriptions/{endpoint-name}/{resource-path}', function() {

    it('should return message', function (done) {
      chai.request(server)
        .put('/subscriptions/' + client.name + '/3303/0/5700')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);

          chai.request(server)
            .delete('/subscriptions/' + client.name + '/3303/0/5700')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(204);

              const id = res.body['async-response-id'];
              chai.request(server)
                .delete('/subscriptions/' + client.name + '/3303/0/5700')
                .end(function (err, res) {

                  done();
                });
            });
        });
    });
  });
});

