#!/bin/bash

(
  export DOCKER_BUILDKIT=1
  export COMPOSE_DOCKER_CLI_BUILD=1
  export RANGER_DB_TYPE=mysql
  # Prevent builder to pull remote image
  # https://github.com/moby/buildkit/issues/2343#issuecomment-1311890308
  export BUILDX_BUILDER=default

  docker compose -f docker-compose.ranger-base.yml -f docker-compose.ranger-build.yml up --pull=never
  docker compose -f docker-compose.ranger-base.yml -f docker-compose.ranger-build.yml cp ranger-build:/home/ranger/dist .
)
