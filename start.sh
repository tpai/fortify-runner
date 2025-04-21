#!/usr/bin/env bash

echo ">Find gunicorn process"
ps aux|grep gunicorn

echo ">Start fortify-runner server"
BASIC_AUTH_USERNAME=admin \
BASIC_AUTH_PASSWORD=secret \
GIT_SSH_KEY=~/.ssh/id_rsa \
DOCKER_USERNAME=username \
DOCKER_PASSWORD=password \
DOCKER_REGISTRY=username.azurecr.io \
SCAN_IMAGE=username.azurecr.io/fortify:23.1.0 \
AZ_STORAGE_URL='https://fortifyreports.blob.core.windows.net/$web' \
AZ_STORAGE_SAS='?sp=racwdl&st=2023-11-10T17:09:35Z&se=2033-10-11T01:09:35Z&spr=https&sv=2022-11-02&sr=c&sig=XXXXXXXXXXXXXXXXXXXXXXXXXXXX' \
python -m gunicorn --bind 0.0.0.0:5000 --workers=2 --threads=4 --worker-class=gthread --log-file gunicorn.log --worker-tmp-dir /dev/shm main:app &

echo ">Verify result"
ps aux|grep gunicorn
