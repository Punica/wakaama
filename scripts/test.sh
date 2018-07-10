#!/bin/sh -x

if [ ! -x ./build/restserver ]
then
    exit 1
fi

openssl genrsa -out private.key 2048
openssl req -days 365 -out certificate.pem -new -x509 -key private.key -subj '/CN=localhost'

openssl genrsa -out other_private.key 2048
openssl req -days 365 -out other_certificate.pem -new -x509 -key other_private.key -subj '/CN=localhost'

GCOV_PREFIX_STRIP=5 GCOV_PREFIX=regular ./build/restserver > /dev/null &
REGULAR_RESTSERVER_PID=$!

GCOV_PREFIX_STRIP=5 GCOV_PREFIX=secure ./build/restserver -c ./tests-rest/secure.cfg > /dev/null &
SECURE_RESTSERVER_PID=$!

cd tests-rest && npm install && npm test
TEST_STATUS=$?

kill -2 $REGULAR_RESTSERVER_PID && wait $REGULAR_RESTSERVER_PID
kill -2 $SECURE_RESTSERVER_PID && wait $SECURE_RESTSERVER_PID

exit $TEST_STATUS
