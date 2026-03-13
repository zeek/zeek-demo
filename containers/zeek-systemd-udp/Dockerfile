# Build stage
FROM docker.io/zeek/zeek-dev:latest AS build

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake \
        g++ \
        gcc \
        libc6-dev \
        liburing-dev \
        libpcap-dev \
        make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/zeek-packet-source-udp
COPY zeek-packet-source-udp ./
WORKDIR /build/zeek-packet-source-udp/build
RUN cmake ../ && make && make -j 2 install

#
# Runtime stage
#
FROM docker.io/zeek/zeek-dev:latest

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && apt-get install --no-install-recommends -y \
    curl \
    ethtool \
    iproute2 \
    net-tools \
    liburing2 \
    jq \
    ncat \
    procps \
    tcpdump \
    systemd \
    systemd-sysv \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# systemd cleanup pieces from the following repo:
#
# https://github.com/j8r/dockerfiles/blob/master/systemd/debian/Dockerfile
#
RUN cd /lib/systemd/system/sysinit.target.wants/ \
    && rm $(ls | grep -v systemd-tmpfiles-setup)

RUN rm -f /lib/systemd/system/multi-user.target.wants/* \
    /etc/systemd/system/*.wants/* \
    /lib/systemd/system/local-fs.target.wants/* \
    /lib/systemd/system/sockets.target.wants/*udev* \
    /lib/systemd/system/sockets.target.wants/*initctl* \
    /lib/systemd/system/basic.target.wants/* \
    /lib/systemd/system/anaconda.target.wants/* \
    /lib/systemd/system/plymouth* \
    /lib/systemd/system/systemd-update-utmp*

# Forward all journald output to the console and select volatile
# storage because we're in a container anyhow.
WORKDIR /etc/systemd/journald.conf.d
RUN printf '[Journal]\nForwardToConsole=yes\nStorage=volatile\n' > container.conf

# Link in the zeek-systemd-generator executable into /etc/systemd/system-generators
# and ensure the multi-user.target pulls in the zeek.target
WORKDIR /etc/systemd/system-generators/
RUN ln -s /usr/local/zeek/bin/zeek-systemd-generator ./zeek-systemd-generator \
    && ln -s /run/systemd/generator/zeek.target /etc/systemd/system/multi-user.target.wants

# Add the Zeek user.
RUN useradd \
    --system \
    --no-create-home \
    --shell /sbin/nologin zeek

# Copy plugins from the build container into the runtime container.
COPY --from=build /usr/local/zeek/lib/zeek/plugins/ /usr/local/zeek/lib/zeek/plugins/

WORKDIR /
COPY entrypoint.sh .
RUN chmod +x ./entrypoint.sh

RUN mv /usr/local/zeek/share/zeek/site/local.zeek /usr/local/zeek/share/zeek/site/local.zeek.orig
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek

WORKDIR /usr/local/zeek/var/spool/zeek

ENTRYPOINT ["/entrypoint.sh"]
