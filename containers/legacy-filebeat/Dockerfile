FROM docker.elastic.co/beats/filebeat:7.9.2

COPY ./filebeat.yml /usr/share/filebeat/filebeat.yml
COPY ./edgecert.key /etc/filebeat/edgecert.key
COPY ./edgecert.pem /etc/filebeat/edgecert.pem
COPY ./rootca.pem /etc/filebeat/rootca.pem
