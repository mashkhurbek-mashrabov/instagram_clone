#!/bin/sh

set -e


ls -la /app/vol
ls -ls /app/vol/static
ls -ls /app/vol/media


whoami
pwd

python manage.py wait_for_db
python manage.py makemigrations
python manage.py migrate
python manage.py collectstatic --noinput

