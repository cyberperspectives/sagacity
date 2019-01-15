FROM php:apache-stretch
COPY conf/docker-php.ini /usr/local/etc/php/php.ini
RUN apt update && apt -y install zlib1g-dev mysql-client
RUN docker-php-ext-install mysqli zip
RUN mkdir /var/log/sagacity && chown www-data:www-data /var/log/sagacity
EXPOSE 80
