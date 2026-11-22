#!/bin/sh
# Le volume monté sur /data appartient souvent à root : on le rend écrivable puis on abandonne les droits root.
set -e
mkdir -p /data
chown -R node:node /data
exec setpriv --reuid=node --regid=node --init-groups --inh-caps=+net_bind_service --ambient-caps=+net_bind_service "$@"
