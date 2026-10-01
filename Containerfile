FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    curl \
    unzip \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 binary package
RUN curl -sSL -o /tmp/radare2.deb https://github.com/radareorg/radare2/releases/download/6.2.2/radare2_6.2.2_amd64.deb \
    && dpkg -i /tmp/radare2.deb \
    && rm -f /tmp/radare2.deb

# Install binlex binary and python extension
RUN curl -sSL -o /tmp/binlex.zip https://github.com/c3rb3ru5d3d53c/binlex/releases/download/v1.1.1/binlex-ubuntu-22.04.zip \
    && unzip /tmp/binlex.zip -d /tmp/binlex_dist \
    && find /tmp/binlex_dist -type f -name "binlex" -exec cp {} /usr/local/bin/ \; \
    && find /tmp/binlex_dist -type f -name "blyara" -exec cp {} /usr/local/bin/ \; \
    && cp /tmp/binlex_dist/pybinlex.cpython-310-x86_64-linux-gnu.so /usr/local/lib/python3.10/dist-packages/pybinlex.so \
    && chmod +x /usr/local/bin/binlex* \
    && rm -rf /tmp/binlex.zip /tmp/binlex_dist

WORKDIR /app

COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /app

CMD ["python3", "-m", "pytest"]
