#!/bin/sh

git clone https://github.com/babelouest/ulfius.git
cd ulfius/
git submodule update --init

cd lib/orcania
make && sudo make install

cd ../yder
make && sudo make install

cd ../..
make
sudo make install
