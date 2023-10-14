#!/bin/sh

set -xe

gcc -DDEBUG -std=c99 -ggdb -Wall -Wextra -Wpedantic -o main main.c
