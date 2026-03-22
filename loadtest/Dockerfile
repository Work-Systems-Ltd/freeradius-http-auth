FROM freeradius/freeradius-server:3.2.7

COPY packets/ /etc/radperf/packets/
COPY run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh

ENTRYPOINT ["/usr/local/bin/run.sh"]
