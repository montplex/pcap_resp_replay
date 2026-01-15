# docker build -t montplex/pcap_resp_replay:1.0.0 .
# need `gradle jar` first
FROM docker.1ms.run/eclipse-temurin:17-jre-jammy

WORKDIR /montplex
COPY build/libs/lib /montplex/lib
COPY build/libs/log4j2.xml /montplex/log4j2.xml

USER root

RUN apt-get update && \
    apt-get install -y libpcap-dev && \
    apt-get clean

# overwrite too offen, skip apt-get install
COPY build/libs/pcap_resp_replay-1.0.0.jar /montplex/pcap_resp_replay-1.0.0.jar

ENTRYPOINT ["java", "-Xms512m", "-Xmx512m", "-jar", "pcap_resp_replay-1.0.0.jar"]