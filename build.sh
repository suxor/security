#!/bin/bash
gcc -g decrypt.c -o decrypt -DDEBUG_LEVEL=$1 -I. -lcrypt -lpthread
