#!/bin/sh

openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout cert.pem -out cert.pem -config ssl-req.conf -extensions 'v3_req'
