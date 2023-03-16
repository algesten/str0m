dtls
====

## OpenSSL

This DTLS impl uses openssl, but we want to change this for a pure Rust variant. To do so,
we want a TLS library as the foundation, and Rust gold standard for that is Rustls. However,
Rustls doesn't currently expose the primitives needed for DTLS. They seem open to a PR
with such additions, and even offered to coach, see 
[this issue](https://github.com/rustls/rustls/issues/40).

Thus the way forward is to:

1. Make a PR in Rustls to expose needed DTLS primitives.
2. Remove dependency on OpenSSL here.
