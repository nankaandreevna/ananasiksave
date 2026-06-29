#!/bin/bash
for i in {600..1000}
do
#vault kv get secret2/write-random-test-$i
vault delete secret2/write-random-test-$i
done