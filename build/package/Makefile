SHELL:=/bin/bash -O extglob
BINARY=zero-knowledge-server
VERSION=1.0
PACKAGES:=$(shell go list ./...)


LDFLAGS=-ldflags "-s -w"

clean:
	@- if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi

run:
	docker build -t ${BINARY} -f Dockerfile  .
	docker run -p 4321:4321  ${BINARY}

build:
	../../scripts/build.sh
