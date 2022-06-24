# double-sha256

Example implementation of Bitcoin-style double SHA-256 with Rust Crypto crates:

```
digest = "0.10.3"
k256 = "0.11.2"
sha2 = "0.10.2"
```

The tests contain an example of using the double SHA256 with ECDSA Secp256k1 
digest  signer.

## License

<p xmlns:dct="http://purl.org/dc/terms/" xmlns:vcard="http://www.w3.org/2001/vcard-rdf/3.0#">
  <a rel="license"
     href="http://creativecommons.org/publicdomain/zero/1.0/">
    <img src="http://i.creativecommons.org/p/zero/1.0/88x31.png" style="border-style: none;" alt="CC0" />
  </a>
  <br />
  To the extent possible under law,
  <a rel="dct:publisher"
     href="https://github.com/agostbiro/double-sha256">
    <span property="dct:title">Agost Biro</span></a>
  has waived all copyright and related or neighboring rights to
  <span property="dct:title">double-sha256</span>.
This work is published from:
<span property="vcard:Country" datatype="dct:ISO3166"
      content="CH" about="https://github.com/agostbiro/double-sha256">
  Switzerland</span>.
</p>