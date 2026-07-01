#
# Build stage for custom zeek-systemd-generator-build
#
FROM docker.io/zeek/zeek-dev:latest AS zeek-systemd-generator-build

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && apt-get install --no-install-recommends -y \
    build-essential \
    cmake \
    g++ \
    git \
    gperf \
    libblkid-dev \
    libbpf-dev \
    libmount-dev \
    libseccomp-dev \
    libpcre2-dev \
    meson \
    ninja-build \
    pkg-config  \
    python3-jinja2 \
    python3-pefile \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY vendor/zeek-systemd-generator ./zeek-systemd-generator
WORKDIR /src/zeek-systemd-generator/build
RUN rm -rf ./* && cmake ../ && make -j

WORKDIR /src
COPY ./vendor/systemd ./systemd
WORKDIR /src/systemd

# Build a stripped down systemd as we only want to supervise Zeek
# in a container, not run a fully fledged system.
RUN rm -rf build && meson setup ./build \
    -Dmode=release \
    -Dapparmor=disabled \
    -Dbacklight=false \
    -Dbashcompletiondir=no \
    -Ddefault-network=false \
    -Dfirstboot=false \
    -Dfuzz-tests=false \
    -Dhibernate=false \
    -Dhwdb=false \
    -Dima=false \
    -Dimds=disabled \
    -Dinitrd=false \
    -Dkernel-install=false \
    -Dlocaled=false \
    -Dmachined=false \
    -Dnetworkd=false \
    -Dnspawn=disabled \
    -Dnsresourced=false \
    -Dnss-myhostname=false \
    -Dnss-mymachines=false \
    -Dnss-resolve=false \
    -Dnss-systemd=false \
    -Doss-fuzz=false \
    -Dpolkit=disabled \
    -Ddbus=false \
    -Dbootloader=false \
    -Dportabled=false \
    -Dpstore=false \
    -Dquotacheck=false \
    -Dremote=disabled \
    -Dresolve=false \
    -Dselinux=disabled \
    -Dslow-tests=false \
    -Dsmack=false \
    -Dstoragetm=false \
    -Dsysext=false \
    -Dsysinstall=false \
    -Dsysupdate=false \
    -Dsysupdated=disabled \
    -Dsysusers=false \
    -Dtests=false \
    -Dtimedated=false \
    -Dtimesyncd=false \
    -Dtmpfiles=false \
    -Dukify=false \
    -Duserdb=false \
    -Dcompat-sysv-interfaces=false \
    -Dvmspawn=disabled \
    -Dzshcompletiondir=no \
    -Ddns-servers="" \
    -Dntp-servers="" \
  && ninja -C build \
  && DESTDIR=/tmp/install/systemd ninja -C build install \
  && du -h --max-depth=4 /tmp/install

#
# Runtime stage
#
FROM docker.io/zeek/zeek-dev:latest

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && apt-get install --no-install-recommends -y \
    curl \
    ethtool \
    iproute2 \
    jq \
    less \
    libblkid1 \
    libbpf1 \
    libmount1 \
    libpcre2-8-0 \
    libseccomp2 \
    liburing2 \
    ncat \
    net-tools \
    procps \
    tcpdump \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Promtail is deprecated, but its easy to setup.
# XXX: SHA256 is for amd64
ENV PROMTAIL_SHA256=8b4e24b91568c851ecb87d7541999d92a90f10953c4fac78827b69887c8241b5
ENV PROMTAIL_VERSION=3.6.7
WORKDIR /etc/promtail

# hadolint ignore=DL4006
RUN curl -m 30 -fL "https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb" \
        -o "promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb" \
    && echo "${PROMTAIL_SHA256}" "promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb" | sha256sum --check \
    && dpkg -i "promtail_${PROMTAIL_VERSION}_$(dpkg --print-architecture).deb" \
    && rm -rf promtail_*deb

RUN mv config.yml config.yml.orig
COPY etc/promtail/config.yml .


COPY --from=zeek-systemd-generator-build /tmp/install/systemd /

# Journal user.
RUN useradd \
    --system \
    --no-create-home \
    --shell /sbin/nologin systemd-journal

# Make multi-user the default target.
# hadolint ignore=DL3059
RUN ln -fs multi-user.target /usr/lib/systemd/system/default.target

#
# Cleanup the systemd installation to avoid starting unnecessary
# services. Taken from the following repo:
#
# https://github.com/j8r/dockerfiles/blob/master/systemd/debian/Dockerfile
#
# hadolint ignore=DL3059,DL3003,DL4006,SC2010
RUN cd /lib/systemd/system/sysinit.target.wants/ \
   && rm -v $(ls | grep -v systemd-tmpfiles-setup)

# Remove preset files and place one to ignore everything.
RUN rm -fv /usr/lib/systemd/system-preset/90-systemd.preset \
 && rm -fv /usr/lib/systemd/user-preset/90-systemd.preset \
 && printf 'ignore *\n' >  /usr/lib/systemd/system-preset/00-ignore-all.preset

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
RUN printf '[Journal]\nForwardToConsole=yes\nStorage=volatile\nReadKMsg=no\n' > container.conf

# Link in the zeek-systemd-generator executable into /etc/systemd/system-generators
# and ensure the multi-user.target pulls in the zeek.target
WORKDIR /etc/systemd/system-generators/
RUN ln -s /usr/local/zeek/bin/zeek-systemd-generator ./zeek-systemd-generator \
    && mkdir -p /etc/systemd/system/multi-user.target.wants \
    && ln -s /run/systemd/generator/zeek.target /etc/systemd/system/multi-user.target.wants

# Add the Zeek user.
RUN useradd \
    --system \
    --no-create-home \
    --shell /sbin/nologin zeek

WORKDIR /usr/local/zeek/share/zeek/site
RUN mv local.zeek local.zeek.orig
COPY local.zeek .

WORKDIR /etc/systemd/system
RUN mv promtail.service promtail.service.orig
COPY etc/systemd/system/promtail.service .

WORKDIR /etc/systemd/system-environment-generators
COPY etc/systemd/system-environment-generators/10-container-env.sh .

# Create a fkae /etc/machine-id to avoid creating one or using container_uuid
RUN echo "00000000000000000000000000000001" > /etc/machine-id

# Install the vendored zeek-systemd-generator version
COPY --from=zeek-systemd-generator-build /src/zeek-systemd-generator/build/zeek-systemd-generator /usr/local/zeek/bin
COPY --from=zeek-systemd-generator-build /src/zeek-systemd-generator/build/zeek-cluster-layout-generator /usr/local/zeek/bin


WORKDIR /usr/local/zeek/var/spool/zeek

# systemd stopsignal
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
