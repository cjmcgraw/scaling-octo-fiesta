FROM debian:bullseye

RUN apt-get update -yqq && apt-get install -y \
    build-essential \
    libpcap-dev \
    tree \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src src/
RUN gcc -v -O3 -o main -Wall src/* -lpcap
RUN mkdir target
RUN chmod +x main
RUN mv main target/
RUN tree .

ENTRYPOINT [ "/app/target/main", "enp71s0"]
