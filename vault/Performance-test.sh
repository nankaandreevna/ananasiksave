#!/bin/sh

# This is passed from Jenkins File
export VAULT_ADDR=$1
export VAULT_TOKEN=$2
export STORAGE_TYPE=$3
export THREADS=$4
export CONNECTIONS=$5
export SECONDS_TO_RUN=$6
export SECRETS_TO_RUN=$7

echo "VAULT_ADDR is $VAULT_ADDR"
echo "VAULT_TOKEN is $VAULT_TOKEN"
echo "STORAGE_TYPE is $STORAGE_TYPE"
echo "THREADS - $THREADS" 
echo "CONNECTIONS - $CONNECTIONS" 
echo "SECONDS_TO_RUN - $SECONDS_TO_RUN" 
echo "SECRETS_TO_RUN - $SECRETS_TO_RUN" 

export VAULT_ADDR=$VAULT_ADDR
vault login $VAULT_TOKEN
if [ $? -ne 0 ] 
  then 
    echo "ERROR LOGGING TO VAULT"
    exit 1
fi

# Uncoment when ready for test

#VAULT AUTH CREATE
 vault auth enable userpass
 vault write auth/userpass/users/loadtester password=benchmark policies=default

#Update write-random-secrets.lua to the path "secret2" if use kv2
 sed -i -e 's+/v1/secret/+/v1/secret2/+g' write-random-secrets.lua
 vault secrets enable -path secret2 -version 1 kv

nohup wrk -t$THREADS -c$CONNECTIONS -d$SECONDS_TO_RUN -H "X-Vault-Token: $VAULT_TOKEN" -s write-random-secrets.lua $VAULT_ADDR -- $SECRETS_TO_RUN > $STORAGE_TYPE-poc-test-write-$SECRETS_TO_RUN-random-secrets-t$THREADS-c$CONNECTIONS-$SECONDS_TO_RUN.log &
# Sleep 25 sec, as script is running on the backend
sleep 35

 echo "Log output for Vault Perf test with Storage type - $STORAGE_TYPE"
 echo "------------------------------------------------------------------------------------------------------"
 echo "------------------------------------------------------------------------------------------------------"
 cat $STORAGE_TYPE-poc-test-write-$SECRETS_TO_RUN-random-secrets-t$THREADS-c$CONNECTIONS-$SECONDS_TO_RUN.log
 echo "------------------------------------------------------------------------------------------------------"
 echo "------------------------------------------------------------------------------------------------------"

# Remove auth after test is complete
 vault auth disable userpass/

# Remove all secrets after test 
if [[ $ENVIRONMENT =  "K8S" ]]; then
vault secrets disable secret2