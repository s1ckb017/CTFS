#!/bin/bash

while true
do
dd if=/dev/urandom count=1 bs=24 > log.hex && cat log.hex | strace ./3x17 2> out.txt

cat out.txt | grep "read(0, NULL, 24)"
if [[ $? -ne 0 ]];
then
    break
fi
sleep 0.10
done


