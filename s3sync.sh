#!/bin/sh

cd target
s3cmd sync doc s3://str0m
s3cmd setacl s3://str0m/doc --acl-public --recursive --verbose
