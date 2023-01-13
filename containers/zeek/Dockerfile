FROM zeek/zeek-dev

RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    ethtool \
    iproute2 \
    net-tools \
    jq \
    ncat \
    procps \
    socat \
    tcpdump


ENV PROMTAIL_SHA256=4cf0150f80ce93a5d6cf2758b782f418c2822262c1fd9747b56bd457d095be9e
ENV PROMTAIL_VERSION=2.7.1
WORKDIR /promtail
RUN curl -m 30 -fL https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb \
        -o promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb

RUN echo ${PROMTAIL_SHA256} promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb | sha256sum --check || ls -lha *

RUN dpkg -i promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb

WORKDIR /etc/promtail
RUN mv config.yml config.yml.orig
COPY etc/promtail/config.yml .

WORKDIR /
COPY entrypoint.sh .
RUN chmod +x ./entrypoint.sh

RUN mv /usr/local/zeek/share/zeek/site/local.zeek /usr/local/zeek/share/zeek/site/local.zeek.orig
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY ./scripts /usr/local/zeek/share/zeek/site/scripts

WORKDIR /var/zeek/logs

ENTRYPOINT ["/entrypoint.sh"]
