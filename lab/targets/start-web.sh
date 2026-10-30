#!/bin/sh
# Copy the read-only site into a writable root so lab.sh can change and fix it.
set -eu
mkdir -p /srv/www /srv/api /srv/shop
cp -R /lab/www/. /srv/www/
cp -R /lab/api/. /srv/api/
cp -R /lab/www/. /srv/shop/
cp /lab/nginx.conf /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
