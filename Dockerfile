# syntax=docker/dockerfile:1.7-labs

FROM rust:bookworm as prefetch
WORKDIR /src/malunpacker
RUN curl -Lo libtorch.zip https://download.pytorch.org/libtorch/cpu/libtorch-cxx11-abi-shared-with-deps-2.1.0%2Bcpu.zip
RUN unzip libtorch.zip
RUN apt update && apt install -y curl libcdio-dev libiso9660-dev libudf-dev libyara-dev build-essential libclang-dev && apt clean

COPY Cargo.toml /src/malunpacker/
RUN mkdir /src/malunpacker/src
RUN echo 'fn main() {}' >/src/malunpacker/src/main.rs
ENV LD_LIBRARY_PATH=/src/malunpacker/libtorch/lib
ENV LIBTORCH=/src/malunpacker/libtorch
RUN cargo b --release 

FROM prefetch as build
WORKDIR /src/malunpacker
COPY Cargo.toml /src/malunpacker/
COPY src /src/malunpacker/src
ENV LD_LIBRARY_PATH=/src/malunpacker/libtorch/lib
ENV LIBTORCH=/src/malunpacker/libtorch
RUN cargo b --release && cp target/*/malunpacker .

FROM debian:bookworm as malunpacker_rootfs
RUN apt update && apt install -y libiso9660-11 libcdio19 libudf0 libyara9 libgomp1 && apt clean
RUN mkdir -p /etc/malunpacker 
COPY --from=build /src/malunpacker/malunpacker /bin/malunpacker
COPY --from=build /src/malunpacker/libtorch /opt/libtorch
ENV LD_LIBRARY_PATH=/opt/libtorch/lib
ENV LIBTORCH=/opt/libtorch
ENV CONF_FROM_ENV=true
VOLUME /etc/malunpacker
WORKDIR /tmp
ENTRYPOINT [ "/bin/malunpacker", "serve" ]
