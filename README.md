# signal-whois

Resolve a signal username or link to a signal uuid.

```sh
signal-whois url 'https://signal.me/#eu/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
signal-whois username signal.03
```

## Compile

```
cargo build --release
./target/release/signal-whois --help
```

## License

This program builds on top of libsignal and is therefore licensed `AGPL-3.0-only`.
