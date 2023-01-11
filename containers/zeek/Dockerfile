FROM zeek/zeek-dev

RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    iproute2 \
    jq \
    ncat \
    procps \
    tcpdump

WORKDIR /
COPY entrypoint.sh .
RUN chmod +x ./entrypoint.sh

RUN mv /usr/local/zeek/share/zeek/site/local.zeek /usr/local/zeek/share/zeek/site/local.zeek.orig
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY ./scripts /usr/local/zeek/share/zeek/site/scripts

ENTRYPOINT ["/entrypoint.sh"]
