#!/bin/sh
# check-out-db.sh

set -e

host="$1"
shift
cmd="$@"

until PGPASSWORD=qwerty1234 psql -h "$host" -U "alias_app" -c '\q'; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

>&2 echo "Postgres is up - executing command"
exit 0