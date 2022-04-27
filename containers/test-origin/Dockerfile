# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.17-alpine

RUN apk update && apk upgrade && apk add git
# RUN go get -u github.com/githubnemo/CompileDaemon

RUN mkdir -p /opt/hello-world
RUN mkdir -p /opt/hello-world/static
COPY ./hello-world.go /opt/hello-world/
COPY ./go.mod /opt/hello-world/
COPY ./static/deflectlogo_RED.png /opt/hello-world/static/

EXPOSE 8080

WORKDIR /opt/hello-world
RUN go get -u github.com/gin-gonic/gin
RUN go build -o test-origin ./hello-world.go
CMD ["./test-origin"]
# ENTRYPOINT CompileDaemon --build="go build hello-world.go" --command="./hello-world"
