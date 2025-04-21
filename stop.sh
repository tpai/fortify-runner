#!/usr/bin/env bash

echo ">Find gunicorn process"
ps aux|grep gunicorn

echo ">Kill gunicorn root process"
ps aux|grep -m 1 gunicorn|awk '{print $2;}'|xargs kill -9

sleep 3

echo ">Verify result"
ps aux|grep gunicorn
