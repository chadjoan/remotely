#!/bin/bash
dmd src/*.d \
		src/c/*.d src/c/libssh/*.d src/c/net/*.d src/c/openssl/*.d \
		src/ssh/*.d \
	-ofremotely -gc -debug -Isrc \
	-L-lssh -L-Llibressl/prefix -L-lssl -L-lcrypto