#!/bin/sh -x

git clone https://github.com/benmcollins/libjwt
cd libjwt
git checkout tags/v1.9.0
autoreconf -i
./configure
make
sudo make install
