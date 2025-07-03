#!/bin/sh -ex

podman network ls -q | grep -q ^step\$ || podman network create step

if [ -d test/postgresql ]
then
	if [ -d test/postgresql/base ]
	then
		rm -r test/postgresql/*
	fi
else
	mkdir test/postgresql
fi

# container names
# database container name must be aligned with test/stepca/config/ca.json
C_PG=t-stepdance-postgresql
C_SC=t-stepdance-stepca
C_NW=host  # step network doesn't work as host test suite needs to connect to oidc provider discovery inside container overwriting issuer causes iss mismatch; running test suite inside container too is an idea but would need a step cli

c_userns_arg=''
if [ "$(id -u)" -gt 0 ]
then
	c_userns_arg='--userns=keep-id'
fi

c_cavol_arg=''
if [ -f /etc/ssl/ca-bundle.pem ]
then
	c_cavol_arg='-v /etc/ssl/ca-bundle.pem:/etc/ssl/certs/ca-certificates.crt:ro'
fi

podman run -d \
	--name=$C_PG \
	--network=$C_NW \
	--rm \
	-e POSTGRES_PASSWORD=ThisIsDumb \
	-p 5432:5432 \
	-v ./test/postgresql:/var/lib/postgresql/data \
	$c_userns_arg \
	docker.io/postgres

i=0
while ! podman exec $C_PG pg_isready
do
	i=$((i+1))
	if [ $i -gt 10 ]
	then
		exit 1
	fi
	sleep 2
done

for x in db user
do
	podman exec $C_PG create$x -Upostgres step
done
podman exec $C_PG psql -Upostgres -c "ALTER USER step WITH LOGIN PASSWORD 'step'; GRANT ALL PRIVILEGES ON DATABASE step TO step; ALTER DATABASE step OWNER to step;"

# shellcheck disable=SC2086 # word splitting is need for $c_cavol_arg
podman run -d \
	--name=$C_SC \
	--network=$C_NW \
	--rm \
	-e DOCKER_STEPCA_INIT_DNS_NAMES=localhost,example.com \
	-e DOCKER_STEPCA_INIT_NAME=TestCA \
	-e DOCKER_STEPCA_INIT_PASSWORD=ThisIsDumb \
	-e DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=true \
	-p 9000:9000 \
	-v ./test/stepca:/home/step \
	$c_userns_arg \
	$c_cavol_arg \
	docker.io/smallstep/step-ca
