#!/bin/sh
cd ../../cmd/zero_knowledge_server/
go build -ldflags "-s -w" -o zero-knowledge-server