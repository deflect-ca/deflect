# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# XXX same as in deflect-analytics-ecosystem
FROM wurstmeister/kafka:0.10.2.0-1
# FROM wurstmeister/kafka:2.13-2.6.0

RUN echo "auto.create.topics.enable=true" > /opt/kafka/config/server.properties

# ENV KAFKA_ADVERTISED_HOST_NAME: ${DOCKER_KAFKA_HOST}  # before run: export DOCKER_KAFKA_HOST=$(ipconfig getifaddr en0)
RUN echo "offsets.topic.replication.factor=1" > /opt/kafka/config/server.properties

EXPOSE 9092
