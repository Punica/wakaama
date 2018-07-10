const chai = require('chai');
const chai_http = require('chai-http');
const fs = require('fs');
const https = require('https');

const should = chai.should();
chai.use(chai_http);

const version_regex = /^1\.\d+\.\d+$/

describe('Secure connection', function () {
  before(function (done) {
    done();
  });

  after(function (done) {
    done();
  });

  describe('GET /version (HTTPS with valid certificate)', function() {

    it('should return 200 and correct version', function(done) {
      const ca = [
          fs.readFileSync('../certificate.pem'),
      ];

      const options = {
        host: 'localhost',
        port: '8889',
        path: '/version',
        ca: ca,
      };

      options.agent = new https.Agent(options);

      https.request(options, (res) => {
        let data = '';
        res.statusCode.should.be.equal(200);

        res.on('data', (chunk) => {
          data = data + chunk;
        });

        res.on('end', () => {
          data.should.match(version_regex);
          done();
        });
      }).end();
    });
  });

  describe('GET /version (HTTPS with invalid certificate)', function() {

    it('should return DEPTH_ZERO_SELF_SIGNED_CERT error code', function(done) {
      const ca = [
          fs.readFileSync('../other_certificate.pem'),
      ];

      const options = {
        host: 'localhost',
        port: '8889',
        path: '/version',
        ca: ca,
      };

      options.agent = new https.Agent(options);

      const req = https.request(options, (res) => {});

      req.on('error', (err) => {
        err.code.should.be.equal('DEPTH_ZERO_SELF_SIGNED_CERT');
        done();
      });

      req.end();
    });
  });
});
