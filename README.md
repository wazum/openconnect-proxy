# openconnect + tinyproxy + microsocks

This Docker image contains an [openconnect client](http://www.infradead.org/openconnect/) (version 8.04 with pulse/juniper support) and the [tinyproxy proxy server](https://tinyproxy.github.io/) for http/s connections (default on port 8888) and the [microsocks proxy](https://github.com/rofl0r/microsocks) for socks5 connections (default on port 8889) in a very small [alpine linux](https://www.alpinelinux.org/) image.

You can find the image on docker hub:
https://hub.docker.com/r/wazum/openconnect-proxy

# Run

First set the variables in `connect` according to your credentials.

	OPENCONNECT_URL=<VPN URL>
	OPENCONNECT_USER=<VPN User>
	OPENCONNECT_OPTIONS="--authgroup <VPN Group> --servercert <VPN Server Certificate> --protocol=<Protocol>"

You can also change the ports used

	HTTPS_PROXY_PORT=8888
	SOCKS5_PROXY_PORT=8889

If you have the password for your connection in a file, provide the path

	PASSWORD_FILE=/path/to/file

Next start the container with 

	chmod 755 ./connect
	./connect

The container will be started in the foreground.
If you want to start it in the background in daemon mode you can call

	./connect -d

In daemon mode you can view the stderr log with

	docker logs <container ID>
	docker logs `docker ps|grep "wazum/openconnect-proxy"|awk -F' ' '{print $1}'`

# Configure proxy

The container is connected via openconnect and you can configure your browser
to use the proxy on port 8888 (see configuration above), 
e.g. with FoxyProxy or any suitable extension.

Or set environment variables with

	export http_proxy="http://127.0.0.1:8888/"
	export https_proxy="http://127.0.0.1:8888/"

composer, git and others use these if you don't use the git+ssh protocol.
For that see the next section.

# ssh through the proxy

You need nc (netcat), corkscrew or something similar to make this work.

Unfortunately some git clients (e.g. Gitkraken) don't use the settings from ssh config
and you can't pull/push from a repository that's reachable (DNS resolution) only through VPN.

## nc (netcat, ncat)

Set a `ProxyCommand` in your `~/.ssh/config` file like

	Host <hostname>
		ProxyCommand            nc -x 127.0.0.1:8889 %h %p

or (depending on your ncat version)

	Host <hostname>
		ProxyCommand            ncat --proxy 127.0.0.1:8889 --proxy-type socks5 %h %p

and your connection will be passed through the proxy.
The above example is for using git with ssh keys.

## corkscrew 

An alternative is _corkscrew_ (e.g. install with `brew install corkscrew` on mac OS)

	Host <hostname>
		ProxyCommand            corkscrew 127.0.0.1 8888 %h %p

# Build

You can build the container yourself with

	docker build -f build/Dockerfile -t wazum/openconnect-proxy:custom ./build

