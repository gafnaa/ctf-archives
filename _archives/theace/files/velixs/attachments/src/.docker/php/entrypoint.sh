#!/bin/sh
set -e

STORAGE_DIR="/var/www/storage"
CACHE_DIR="/var/www/bootstrap/cache"

mkdir -p "$STORAGE_DIR" "$CACHE_DIR"

chown -R www-data:www-data "$STORAGE_DIR" "$CACHE_DIR"
chmod -R 775 "$STORAGE_DIR" "$CACHE_DIR"


composer install
php artisan migrate:fresh
php artisan db:seed
php artisan storage:link
php artisan key:generate

chmod +t /var/www/storage /var/www/bootstrap/cache
chmod 2775 "$STORAGE_DIR" "$CACHE_DIR"

for dir in "$STORAGE_DIR"/*; do
  if [ -d "$dir" ]; then
    chown root:www-data "$dir"
    chmod 2775 "$dir"
    find "$dir" -type d -exec chmod 2775 {} +
    find "$dir" -type f -exec chmod 664 {} +
  fi
done

chown -R root:www-data "$STORAGE_DIR"
chmod -R 3775 "$STORAGE_DIR"

exec "$@"