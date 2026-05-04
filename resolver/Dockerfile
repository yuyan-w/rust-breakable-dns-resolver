FROM rust:1.95.0

WORKDIR /app

RUN cargo install cargo-watch

COPY . .

EXPOSE 33053/udp

CMD ["cargo", "watch", "-x", "run"]