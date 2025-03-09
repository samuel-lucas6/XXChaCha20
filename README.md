# XXChaCha20: eXtended-nonce XChaCha20
XXChaCha20 is a variant of [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) without the `\x00\x00\x00\x00` nonce prefix to obtain a 224-bit nonce.

This is actually better from a performance standpoint because there's no need to pad part of the nonce. However, the internal counter is only 32 bits when [some](https://doc.libsodium.org/advanced/stream_ciphers/xchacha20) XChaCha20 implementations support a 64-bit counter. With that said, this shouldn't cause any real-world problems (e.g., due to [stream encryption](https://eprint.iacr.org/2015/189)).
