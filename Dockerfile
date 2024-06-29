FROM alpine:3

RUN apk add --no-cache pdns pdns-backend-pipe python3

EXPOSE 53/tcp 53/udp

COPY dynamicdns/backend.py /opt/dynamicdns/

COPY dynamicdns/backend.conf /opt/dynamicdns/

COPY config/pdns/pdns.conf /etc/pdns/pdns.conf

RUN chmod +x /opt/dynamicdns/backend.py

CMD ["/usr/sbin/pdns_server", "--daemon=no", "--disable-syslog", "--write-pid=no"]