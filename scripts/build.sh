#!/bin/sh

mkdir build && cd build && cmake -DCODE_COVERAGE=ON ../examples/rest-server && make

