sserl
=====

## A simple shadowsocks impletation.

Supoorted features:
- [x] TCP
- [ ] UDP

Supported ciphers:
- [x] aes_128_gcm
- [x] aes_256_gcm
- [x] chacha20_poly1305

Build
-----

    $ rebar3 release --all 

Run
---

### Client

    $ ADDR=\"127.0.0.1\" PORT=8388 LOCAL_PORT=1080 PASSWORD=\"!barfoo\" METHOD=chacha20_poly1305 _build/default/rel/client/bin/client foreground          

### Server

    $ PORT=8388 PASSWORD=\"!barfoo\" METHOD=chacha20_poly1305 _build/default/rel/server/bin/server foreground    

Configuration
-------------

Config by environment variable.

### Client:

* ADDR: remote address
* PORT: remote port
* LOCAL_PORT: local port of socks5 server
* PASSWORD: password
* METHOD: encryption method, in [aes_128_gcm, aes_256_gcm, chacha20_poly1305].

### Server:

* PORT: port
* PASSWORD: password
* METHOD: encryption method, in [aes_128_gcm, aes_256_gcm, chacha20_poly1305].



