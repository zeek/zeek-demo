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

WORKDIR /
COPY entrypoint.sh .
RUN chmod +x ./entrypoint.sh

RUN mv /usr/local/zeek/share/zeek/site/local.zeek /usr/local/zeek/share/zeek/site/local.zeek.orig
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY ./scripts /usr/local/zeek/share/zeek/site/scripts

WORKDIR /var/zeek/

ENTRYPOINT ["/entrypoint.sh"]
