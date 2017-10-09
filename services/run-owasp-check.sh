#!/bin/bash

DIR="$(dirname "$0")"
cd $DIR 

mvn dependency-check:check
