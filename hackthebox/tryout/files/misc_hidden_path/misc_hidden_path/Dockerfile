FROM node:18-alpine

RUN adduser -D -u 1010 -g 1010 -s /bin/sh www

COPY challenge/ /www/

WORKDIR /www
RUN npm install express

RUN chown -R www:www /www/

EXPOSE 1337

CMD node app.js
