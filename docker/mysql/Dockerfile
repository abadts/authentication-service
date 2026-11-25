FROM mysql:8.0

ENV MYSQL_DATABASE=invex
ENV MYSQL_USER=admin
ENV MYSQL_PASSWORD=admin
ENV MYSQL_ROOT_PASSWORD=admin

COPY init/01-databases.sql /docker-entrypoint-initdb.d/01-databases.sql

EXPOSE 3306
