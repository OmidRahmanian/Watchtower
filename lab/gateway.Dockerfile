# Publishes the lab dashboard on the host's loopback interface.
FROM nginx:1.27-alpine
COPY gateway.conf /etc/nginx/conf.d/default.conf
