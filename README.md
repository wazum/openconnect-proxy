# openconnect + tinyproxy

This Docker image contains an [openconnect client](http://www.infradead.org/openconnect/) and the [tinyproxy proxy server](https://tinyproxy.github.io/)
on a very small [alpine linux](https://www.alpinelinux.org/) image (requires around 60 MB of download).

# Run

First set the variables in `connect` according to your credentials.

	OPENCONNECT_URL=<VPN URL>
	OPENCONNECT_USER=<VPN User>
	OPENCONNECT_OPTIONS="--authgroup <VPN Group> --servercert <VPN Server Certificate>"
	PROXY_PORT=8888

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

(composer, git and others use these)

# ssh through the proxy

Install _corkscrew_ (e.g. with `brew install corkscrew` on macOS)
and if the container is running (see above) connect with

	./connect ssh <user>@<host>

or if you always use the same port simply add the following in your 
`~/.ssh/config`

	Host <hostname>
		User <user>
		ProxyCommand corkscrew 127.0.0.1 8888 %h %p

and your connection will be passed through the proxy.

# Build

You can build the container yourself with

	docker build -f build/Dockerfile -t wazum/openconnect-proxy:latest ./build

