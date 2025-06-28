#!/bin/sh
set -e

make run_migrations

exec /bin/server