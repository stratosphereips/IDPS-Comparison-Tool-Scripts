FROM ubuntu:20.04
# To avoid user interaction when installing libraries
ENV DEBIAN_FRONTEND=noninteractive

RUN  apt update  \
     && apt install -y --no-install-recommends software-properties-common  \
     && add-apt-repository ppa:oisf/suricata-beta  \
     && apt update  \
     && apt upgrade  \
     && apt install -y --no-install-recommends  \
    suricata \
    tree \
    tmux \
    nano \
    wget \
    ca-certificates \
    git \
    curl \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    python3-certifi \
    python3-dev \
    build-essential \
    file \
    lsof \
    iptables \
    iproute2 \
    python3-tzlocal \
    net-tools \
    vim \
    less

RUN pip3 install --no-cache-dir --upgrade pip
WORKDIR /suricata/output
CMD /bin/bash