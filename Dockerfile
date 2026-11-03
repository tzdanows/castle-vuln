FROM rust:1.93
WORKDIR /app
COPY . .
RUN cargo build --release
EXPOSE 3000
CMD ["./target/release/castle-vuln"]
