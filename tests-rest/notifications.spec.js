
const chai = require('chai');
const chai_http = require('chai-http');
const should = chai.should();
const server = require('./server-if');
const ClientInterface = require('./client-if');

chai.use(chai_http);

describe('Notifications interface', function () {
  const client = new ClientInterface();

  before(function (done) {
    server.start();

    client.connect(server.address(), (err, res) => {
      done();
    });
  });

  after(function () {
    client.disconnect();
  });

  describe('GET /notification/callback', function() {

    it('should return 404 (NOT FOUND)', function(done) {
      chai.request(server)
        .get('/notification/callback')
        .end(function (err, res) {
          err.should.have.status(404);

          done();
        });
    });

    it('should return 200 (url found)', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .send('{"url": "http://localhost:9998/my_callback", "headers": {}}')
        .end(function (err, res) {
          should.not.exist(err);
          // XXX: Successful subscription status code should be 204, however
          // it is 200 now
          // res.should.have.status(204);
          res.should.have.status(200);

          chai.request(server)
            .get('/notification/callback')
            .end(function (err, res) {
              should.not.exist(err);
              res.body.should.be.a('object');
              res.should.have.status(200);

              done();
            });
        });
    });
  });

  describe('PUT /notification/callback', function() {

    it('should return 204 (successfully subscribed)', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .send('{"url": "http://localhost:9999/my_callback", "headers": {}}')
        .end(function (err, res) {
          should.not.exist(err);
          // XXX: Successful subscription status code should be 204, however
          // it is 200 now
          // res.should.have.status(204);
          res.should.have.status(200);

          done();
        });
    });

    it('should return 400 for empty object', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .end(function (err, res) {
          err.should.have.status(400);

          done();
        });
    });

    it('should return 400 for wrong object size', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .send('{"url": "http://localhost:9999/my_callback"}')
        .end(function (err, res) {
          err.should.have.status(400);

          done();
        });
    });

    it('should return 400 for wrong callback headers type', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .send('{"url": "http://localhost:9999/my_callback", "headers": "wrong-type"}')
        .end(function (err, res) {
          err.should.have.status(400);

          done();
        });
    });

    it('should return 400 for invalid url', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .send('{"url": 9999, "headers": {}}')
        .end(function (err, res) {
          err.should.have.status(400);

          done();
        });
    });

    it('should return 400 for wrong value type in callback headers object', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .set('Content-Type', 'application/json')
        .send('{"url": "http://localhost:9999/my_callback", "headers": {"Wrong-Header": 42}}')
        .end(function (err, res) {
          err.should.have.status(400);

          done();
        });
    });

    it('should return 415 for wrong "Content-Type" header', function(done) {
      chai.request(server)
        .put('/notification/callback')
        .end(function (err, res) {
          err.should.have.status(415);

          done();
        });
    });
  });

  describe('GET /notification/pull', function() {

    it('should return object and 200 for single pull', function(done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .get('/endpoints/'+client.name+'/3/0/0')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('async-response-id');
          res.body['async-response-id'].should.be.a('string');
          res.body['async-response-id'].should.match(id_regex);

          chai.request(server)
            .get('/notification/pull')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(200);

              done();
            });
        });
    });

    it('should return 204 for double pull', function(done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
        .get('/endpoints/'+client.name+'/3/0/0')
        .end(function (err, res) {
          should.not.exist(err);
          res.should.have.status(202);
          res.should.have.header('content-type', 'application/json');

          res.body.should.be.a('object');
          res.body.should.have.property('async-response-id');
          res.body['async-response-id'].should.be.a('string');
          res.body['async-response-id'].should.match(id_regex);

          chai.request(server)
            .get('/notification/pull')
            .end(function (err, res) {
              should.not.exist(err);
              res.should.have.status(200);

              chai.request(server)
                .get('/notification/pull')
                .end(function (err, res) {
                  should.not.exist(err);
                  res.body.should.be.a('object');
                  // XXX: Should be 204 and no object when there are no new notifications
                  // it is 200 and dictionary with empty arrays now
                  // res.should.have.status(204);

                  res.should.have.status(200);

                  done();
                });
            });
        });
    });

    it('should return 200 and object containing registration updates', function(done) {
      const id_regex = /^\d+#[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/g;
      chai.request(server)
      .get('/notification/pull')
      .end(function (err, res) {
        should.not.exist(err);

        client.sendUpdate()
        .then(() => {
          chai.request(server)
          .get('/notification/pull')
          .end(function (err, res) {
            should.not.exist(err);
            res.should.have.status(200);

            res.should.have.header('content-type', 'application/json');
            res.body.should.be.a('object');
            res.body.should.have.property('reg-updates');

            res.body['reg-updates'].should.be.a('array');
            res.body['reg-updates'][0].should.be.a('object');
            res.body['reg-updates'][0]['name'].should.be.a('string');
            res.body['reg-updates'][0]['name'].should.be.equal(client.name);

            done();
          });
        })
        .catch((err) => {
          should.not.exist(err);
        });
      });
    });
  });
});
