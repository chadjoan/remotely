#!/bin/bash
mkdir -p bin
dmd src/*.d \
		src/c/*.d src/c/libssh/*.d src/c/net/*.d src/c/openssl/*.d \
		src/ssh/*.d \
	-ofbin/remotely -gc -debug -Isrc \
	-L-lssh -L-Llibressl/prefix -L-lssl -L-lcrypto
