# Base image PHP with Apache
FROM php:8.2-apache

# Install dependencies
RUN apt-get update && apt-get install -y \
    libzip-dev \
    zip \
    && docker-php-ext-install zip

# Activate mod_rewrite for Apache
RUN a2enmod rewrite

# Copy file challenge to container
COPY ./src/ /var/www/html/

# Set permission
RUN chown -R www-data:www-data /var/www/html/

# Create flag.txt
RUN echo "HIDC2025{find_me}" > /flag.txt && \
    chmod 644 /flag.txt && \
    chown root:root /flag.txt

# Expose port 80
EXPOSE 80

# Start Apache
CMD ["apache2-foreground"]
