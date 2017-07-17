#!/bin/bash

DIR="$(readlink -f "$0")"
cd $DIR 

mvn dependency-check:check
