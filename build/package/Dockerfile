FROM golang

ENV GOPRIVATE "github.com/tuckyapps"

COPY . /go/src/github.com/tuckyapps/zero-knowledge-proof
WORKDIR /go/src/github.com/tuckyapps/zero-knowledge-proof

RUN make build

CMD ./cmd/zero_knowledge_server/lit-knowledge-server

EXPOSE 4321
