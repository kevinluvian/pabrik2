FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# # --- CHECKPOINT 1: Repositories ---
# # We enable 'universe' so we can find packages like python3-pip later.
RUN sed -i 's/main restricted/main restricted universe/g' /etc/apt/sources.list

# --- CHECKPOINT 2: System Tools (Heavy Download) ---
# We run 'update' here and install the heavy system tools.
# If this succeeds, Docker saves this layer forever.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    wget \
    ca-certificates \
    libncurses5 \
    libpq-dev \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    tar \
    gzip \
    libcairo2-dev \
    build-essential \
    python3-dev \
    libgirepository1.0-dev

# --- CHECKPOINT 3: The Ancient Library (Fragile Network Step) ---
# We isolate this because the download server (kernel.org) might be flaky.
# If this fails, you only retry this specific wget.
COPY libstdc++5_3.3.6-30_amd64.deb /tmp/libstdc++5_3.3.6-30_amd64.deb
RUN dpkg -i /tmp/libstdc++5_3.3.6-30_amd64.deb && rm /tmp/libstdc++5_3.3.6-30_amd64.deb

# --- CHECKPOINT 5: Install Firebird ---
# This relies on your local file, so it's fast.
COPY FirebirdSS-2.1.7.18553-0.amd64.tar.gz /tmp/firebird.tar.gz

RUN cd /tmp && \
    tar -xzf firebird.tar.gz && \
    cd FirebirdSS-2.1.7.18553-0.amd64 && \
    (echo ""; echo "masterkey") | ./install.sh && \
    cd / && \
    rm -rf /tmp/firebird.tar.gz /tmp/FirebirdSS*

COPY . /home/app

WORKDIR /home/app

RUN pip3 install -r requirements.txt

EXPOSE 3050

ENTRYPOINT ["/home/app/start.sh"]
