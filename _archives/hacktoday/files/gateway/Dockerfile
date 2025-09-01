FROM openresty/openresty:alpine

COPY ./nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY ./www /www
RUN echo "hacktoday{test}" > /flag
RUN echo "test" > /password

EXPOSE 80

CMD ["sh", "-c", "openresty -g 'daemon off;'"]