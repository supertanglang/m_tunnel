

[![MIT licensed][1]][2]  [![Build Status][3]][4]

[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE

[3]: https://travis-ci.org/lalawue/m_tunnel.svg?branch=master
[4]: https://travis-ci.org/lalawue/m_tunnel





# About

m_tunnel was a secure TCP tunnel with sock5 proxy interface, action like shadowsocks.
It's lightweight and play well with [m_kcptun](https://github.com/lalawue/m_kcptun) or
[kcptun](https://github.com/xtaci/kcptun), using RC4 crypto from cloudwu's [mptun](https://github.com/cloudwu/mptun).

only support IPV4, under Linux/MacOS/FreeBSD/Windows, base on [m_net](https://github.com/lalawue/m_net),
[m_foundation](https://github.com/lalawue/m_foundation), [m_dnscnt](https://github.com/lalawue/m_dnscnt).





# Features

- only one tcp connection between local and remote
- authentication only once, speed up every request
- concurrency DNS query in remote
- transport compressed data with [FastLZ](https://github.com/ariya/FastLZ)
- socks5 proxy interface 
- support Windows





# QuickStart

Download precompiled [Release](https://github.com/lalawue/m_tunnel/releases).





# Compile & Running

1. in Linux/MacOS/FreeBSD, first compile the source

```
# git clone https://github.com/lalawue/m_tunnel.git
# cd m_tunnel
# git submodule update --init --recursive
# make release
```

in Windows, using VS2017 under vc dir, the .vcxproj just ready for client side.

in FreeBSD, using gmake.



2. run remote & local
```
# ./tun_remote.out -r "192.168.2.101:7777" -u username -p password
# ./tun_local.out -l "127.0.0.1:8888" -r "192.168.2.101:7777" -u username -p password
```
