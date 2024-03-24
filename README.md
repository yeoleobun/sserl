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

    $ cd _build/prod/rel/client
    $ bin/client cnosole

### Server

    $ cd _build/prod/rel/server
    $ bin/server cnosole

### with custom configuration:
    
    $ erl -boot releases/0.1.0/start -config releases/0.1.0/sys    


Configuration
-------------
### Server:

port: Listening Port

password: Password used to derivate session key

method: cipher method

### Client:

password & method: same as Server configuration

address: remote address

port: remote port

local_port: local port of socks5 server

### Example
config/sys.config
```
[
  {server,[{port,8388},{password,"barfoo!"},{method,chacha20_poly1305}]},
  {client,[{address,{127,0,0,1}},{port,8388},{local_port,1080},{password,"barfoo!"},{method,chacha20_poly1305}]}
].

```


