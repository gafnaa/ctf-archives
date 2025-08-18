FROM python:3.11-alpine

# Install packages
RUN apk update \
    && apk add --no-cache --update mariadb mariadb-dev mariadb-client supervisor gcc musl-dev mariadb-connector-c-dev

# Upgrade pip
RUN python -m pip install --upgrade pip

# Copy flag
COPY flag.txt /flag.txt

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 8099

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# create database and start supervisord
COPY --chown=root start.sh /start.sh
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]