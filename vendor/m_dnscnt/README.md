

[![MIT licensed][1]][2]  [![Build Status][3]][4]


[1]: https://img.shields.io/badge/license-MIT-blue.svg
[2]: LICENSE

[3]: https://travis-ci.org/lalawue/m_dnscnt.svg?branch=master
[4]: https://travis-ci.org/lalawue/m_dnscnt


# About

m_dnscnt is DNS query client/library with concurrency,  on-blocking interface, base on
[m_net](https://github.com/lalawue/m_net), [m_foundation](https://github.com/lalawue/m_foundation).

Support Linux/MacOS/FreeBSD/Windows.



# Features

- query every DNS server at one time, pick the very first response
- query same domain only once
- standalone/library mode with concurrency, non-blocking interface
- local cache 48 hrs


# Usage

## 1. standalone mode

```c
$ git submodule update --init --recursive
$ make # gmake in FreeBSD
$ ./dns_cnt.out 30000 'google.com' 'youtube.com' 'facebook.com'
$ ./dns_cnt.out 30000 'google.com' 'google.com' 'google.com' 'google.com'
```

## 2. library mode

require [m_net](https://github.com/lalawue/m_net), [m_foundation](https://github.com/lalawue/m_foundation).

using API in [mdns_cnt.h](https://github.com/lalawue/m_dnscnt/blob/master/src/mdns_cnt.h).



