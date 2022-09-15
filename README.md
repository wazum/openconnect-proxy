# openconnect + tinyproxy + microsocks

This Docker image contains an [openconnect client](http://www.infradead.org/openconnect/) (version 8.04 with pulse/juniper support) and the [tinyproxy proxy server](https://tinyproxy.github.io/) for http/https connections (default on port 8888) and the [microsocks proxy](https://github.com/rofl0r/microsocks) for socks5 connections (default on port 8889) in a very small [alpine linux](https://www.alpinelinux.org/) image (around 20 MB).

You can find the image on docker hub:
https://hub.docker.com/r/wazum/openconnect-proxy

# Requirements

If you don't want to set the environment variables on the command line
set the environment variables in a `.env` file:

	OPENCONNECT_URL=<Gateway URL>
	OPENCONNECT_USER=<Username>
	OPENCONNECT_PASSWORD=<Password>
	OPENCONNECT_OPTIONS=--authgroup <VPN Group> \
		--servercert <VPN Server Certificate> --protocol=<Protocol> \
		--reconnect-timeout 86400

_Don't use quotes around the values!_

See the [openconnect documentation](https://www.infradead.org/openconnect/manual.html) for available options. 

Either set the password in the `.env` file or leave the variable `OPENCONNECT_PASSWORD` unset, so you get prompted when starting up the container.

You can also use multi-factor one-time-password codes in two different ways. If your connection uses a time-based OTP (like Google Authenticator), you can provide the key, and the entrypoint will generate and provide the code whenever it tries to connect:

	OPENCONNECT_TOTP_SECRET=<Key for TOTP>

Otherwise, you can generate the one-time-password yourself and pass it when you start the server:

	OPENCONNECT_MFA_CODE=<Multi factor authentication code>

# Run container in foreground

To start the container in foreground run:

	docker run -it --rm --privileged --env-file=.env \
	  -p 8888:8888 -p 8889:8889 wazum/openconnect-proxy:latest

The proxies are listening on ports 8888 (http/https) and 8889 (socks). Either use `--net host` or `-p <local port>:8888 -p <local port>:8889` to make the proxy ports available on the host.

Without using a `.env` file set the environment variables on the command line with the docker run option `-e`:

	docker run … -e OPENCONNECT_URL=vpn.gateway.com/example \
	-e OPENCONNECT_OPTIONS='<Openconnect Options>' \
	-e OPENCONNECT_USER=<Username> …

# Run container in background

To start the container in daemon mode (background) set the `-d` option:

	docker run -d -it --rm …

In daemon mode you can view the stderr log with `docker logs`:

	docker logs `docker ps|grep "wazum/openconnect-proxy"|awk -F' ' '{print $1}'`

# Use container with docker-compose

	vpn:
	  container_name: openconnect_vpn
	  image: wazum/openconnect-proxy:latest
	  privileged: true
	  env_file:
	    - .env
	  ports:
	    - 8888:8888
	    - 8889:8889
	  cap_add:
	    - NET_ADMIN
	  networks:
	    - mynetwork


Set the environment variables for _openconnect_ in the `.env` file again (or specify another file) and 
map the configured ports in the container to your local ports if you want to access the VPN 
on the host too when running your containers. Otherwise only the docker containers in the same
network have access to the proxy ports.

# Route traffic through VPN container

Let's say you have a `vpn` container defined as above, then add `network_mode` option to your other containers:

	depends_on:
	  - vpn
	network_mode: "service:vpn"

Keep in mind that `networks`, `extra_hosts`, etc. and `network_mode` are mutually exclusive!

# Configure proxy

The container is connected via _openconnect_ and now you can configure your browser
and other software to use one of the proxies (8888 for http/https or 8889 for socks).

For example FoxyProxy (available for Firefox, Chrome) is a suitable browser extension.

You may also set environment variables:

	export http_proxy="http://127.0.0.1:8888/"
	export https_proxy="http://127.0.0.1:8888/"

composer, git (if you don't use the git+ssh protocol, see below) and others use these.

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

# Support

You like using my work? Get something for me (surprise! surprise!) from my wishlist on [Amazon](https://smile.amazon.de/hz/wishlist/ls/307SIOOD654GF/) or [help me pay](https://www.paypal.me/wazum) the next pizza or Pho soup (mjam). Thanks a lot!


