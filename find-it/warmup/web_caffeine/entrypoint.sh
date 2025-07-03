#!/bin/bash

# Secure entrypoint
chmod 600 /start.sh

# Initialize & Start MariaDB
mkdir -p /run/mysqld
chown -R mysql:mysql /run/mysqld
mysql_install_db --user=mysql --ldata=/var/lib/mysql
mysqld --user=mysql --console --skip-networking=0 &

# Wait for mysql to start
while ! mysqladmin ping -h'localhost' --silent; do echo 'not up' && sleep .2; done

# Populate database
mysql -u root << EOF
DROP DATABASE IF EXISTS caffeine;
CREATE DATABASE caffeine;
CREATE TABLE caffeine.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL,
    role varchar(255) NOT NULL DEFAULT 'user'
);

CREATE TABLE caffeine.products (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    name varchar(255) NOT NULL,
    price varchar(255) NOT NULL,
    description TEXT NOT NULL
);

CREATE USER 'syulit'@'localhost' IDENTIFIED BY 'syulit';
GRANT SELECT, INSERT, UPDATE ON caffeine.users TO 'syulit'@'localhost';
GRANT SELECT, INSERT, UPDATE ON caffeine.products TO 'syulit'@'localhost';

FLUSH PRIVILEGES;
EOF

mkdir /opt/manualFiles

/usr/bin/supervisord -c /etc/supervisord.conf