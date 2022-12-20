FROM rust:1.65

RUN apt-get update
RUN apt-get install -y cmake libclang-dev
RUN cargo install --path .

WORKDIR /usr/src/prew
COPY . .

CMD ["prew"]
