#!/bin/bash

# build the docker containers and start them up

cd "${0%/*}"
sudo docker compose up --build -d 