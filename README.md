
# About

m_tunnel was a secure TCP tunnel with sock5 proxy interface, action like shadowsocks, but it only keeps 1 tcp connection between local and remote. It's lightweight and play well with https://github.com/xtaci/kcptun.

only support IPV4, under MacOS/Linux/Windows. 

using RC4 crypto from cloudwu's mptun https://github.com/cloudwu/mptun/.





# Features

- only one tcp connection between local and remote
- authentication only once, speed up every request
- socks5 proxy interface 
- support Windows




# QuickStart

Download precompiled [Release](https://github.com/lalawue/m_tunnel/releases).





# Install & Running

in MacOS/Linux, just

```
# make
# ./tun_remote.out config/remote_conf.txt # in server
# ./tun_local.out config/local_conf.txt   # in local
```

in Windows, using VS2017 under vc dir.





# Configure

Under config dir, something like:

```
# 
DEBUG_FILE=stdout

# as sock5 front
LOCAL_MODE=FRONT

# local ip address
LOCAL_IP=127.0.0.1
LOCAL_PORT=1080

# remote ip address
REMOTE_IP=192.168.2.101
REMOTE_PORT=9871

REMOTE_USERNAME=112233
REMOTE_PASSWORD=123456
```
