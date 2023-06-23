# nforwardauth

[![Actions status](https://github.com/nosduco/nforwardauth/workflows/CI/badge.svg)](https://github.com/nosduco/nforwardauth/actions)
[![Docker Image Size](https://img.shields.io/docker/image-size/nosduco/nforwardauth)](https://hub.docker.com/r/nosduco/nforwardauth)
[![Docker Image Version](https://img.shields.io/docker/v/nosduco/nforwardauth?sort=semver)](https://hub.docker.com/r/nosduco/nforwardauth)

nforwardauth is an extremely lightweight, blazing fast forward auth service that lets you use a single authentication middleware for all your sites. It is intended for use with reverse proxies like [Traefik](https://github.com/traefik/traefik), [Caddy](https://github.com/caddyserver/caddy), [nginx](https://nginx.com), and others to allow/deny access via an auth wall.

![Screenshot](https://github.com/nosduco/nforwardauth/blob/main/screenshot.png)

## Why nforwardauth?

The inspiration for nforwardauth came from my frustration with using basic auth as a simple way to protect my self-hosted server applications. I wanted something that was more user-friendly and streamlined, and that didn't require me to authenticate with every site and allowed me to autofill my passwords with my password manager.

I also wanted something that could be used in conjunction with other self-host server homepages like [Homer](https://github.com/bastienwirtz/homer) and [homepage](https://github.com/benphelps/homepage). I was impressed with how [Organizr's](https://github.com/organizr) forwardauth worked, but I found it to be too complex and heavy for my needs. That's why I decided to create nforwardauth, a simple and lightweight alternative that gets the job done without any unnecessary bells and whistles.

## How it works

Here is a simple illustration of how nforwardauth integrates with reverse proxies. (Note: you do not have to protect all sites with forwardauth as they don't have to be configured with the middleware):

![Diagram](https://github.com/nosduco/nforwardauth/blob/main/diagram.png)

When you visit a route/host that is protected by nforwardauth, the server will first forward the request to nforwardauth which will check whether or not your request contains a valid access token. If your request does not, you will be redirected to the nforwardauth login page. Upon logging in, you will be redirected to the URI of your initial request.

nforwardauth uses a `passwd` file to store valid credentials. Currently, it only supports username and password combinations (similar to that of HTTP basic auth).

***Note: You can still pass basic auth in the URL and skip the login page. This compatibility exists for applications like nzb360.***

## Getting started

#### How the `passwd` file works

nforwardauth uses a `passwd` file to store usernames and hashed passwords for authentication. To use nforwardauth, you'll need to create a `passwd` file and mount it as a volume when you run the container.

Here's an example of how to create an initial `passwd` file with a single user named `test` and the password `test`. We'll use the `mkpasswd` command to generate a sha-512 hashed version of the password and echo the username and hashed password into the `passwd` file.

```bash
echo "test:$(mkpasswd -m sha-512 test)" >> /path/to/passwd

```

The `passwd` file should contain one line per use in the format `username:hased_password`.

When you run the nforwardauth container, you should mount the `passwd` file as a volume with the `-v` option when using the command line, like this:
```bash
docker run -p 3000:3000 \
  -e TOKEN_SECRET=example-secret-123 \
  -e AUTH_HOST=nforwardauth.localhost.com \
  -v /path/to/passwd:/passwd \
  nosduco/nforwardauth:v1
```

With your `passwd` file mounted, nforwardauth will use it to authenticate users when they access sites with the forwardauth middleware. You will only need to login once to access all sites behind the middleware.

#### Simple configuration:

Here is a very simple configuration using Traefik v2 and protecting a simple `whoami` container behind the forwardauth middleware.

```yaml
version: '3'

services:
  traefik:  # Basic traefik v2 configuration
    image: traefik:v2.9
    command: --providers.docker
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro # Mount docker socket as read-only

  nforwardauth: # nforwardauth example configuration (for use behind HTTPS by default)
    image: nosduco/nforwardauth:v1
    environment:
      - TOKEN_SECRET=example-secret-123 # Secret to use when signing auth token
      - AUTH_HOST=nforwardauth.yourdomain.com # Where nforwardauth can be accessed/redirected to for login
    labels:
      - "traefik.http.routers.nforwardauth.rule=Host(`nforwardauth.yourdomain.com`)"
      - "traefik.http.middlewares.nforwardauth.forwardauth.address=http://nforwardauth:3000"
      - "traefik.http.services.nforwardauth.loadbalancer.server.port=3000"
    volumes:
      - "/path/to/passwd:/passwd:ro" # Mount local passwd file at /passwd as read only

  whoami: # whoami example container accessible at "whoami.yourdomain.com" behind nforwardauth middleware
    image: traefik/whoami
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.yourdomain.com`)"
      - "traefik.http.routers.whoami.middlewares=nforwardauth"
```
In the example, if you navigate to `whoami.yourdomain.com` you will be redirected to the `nforwardauth` login page. Once you sign in with valid credentials, you will be redirected back to `whoami.yourdomain.com` and subsequent visits to the site will not require a login.

Look at the `examples` directory in the repository or the below details section for more examples

<details>
  <summary>For more advanced scenarios and configurations</summary>

  #### Advanced configuration
  
  Here is an example similar to the above above to support HTTP by using the available configuration properties

  ```yaml
  version: '3'

  services:
    traefik: 
      image: traefik:v2.9
      command: --api.insecure=true --providers.docker
      ports:
        - "80:80" # HTTP port
        - "8080:8080" # Web UI port (enabled by --api.insecure=true)
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock:ro # Mount docker socket as read-only

    nforwardauth:
      image: nosduco/nforwardauth:v1
      environment:
        - TOKEN_SECRET=example-secret-123 # Secret to use when signing auth token
        - COOKIE_SECURE=false # Do not set cookies as secure (WARNING: ONLY USE IN DEV OR LAN-ONLY HOSTS)
        - AUTH_HOST=nforwardauth.localhost.com # (required)
        - COOKIE_DOMAIN=localhost.com # Set domain for the cookies. This value will allow cookie and auth on *.yourdomain.com (including base domain)
        - COOKIE_NAME=nforwardauth # Set name for the cookie (helpful if running multiple instances of nforwardauth to prevent collision)
        - PORT=3000 # Set specific port to listen on 
      labels:
        - "traefik.http.routers.nforwardauth.rule=Host(`nforwardauth.localhost.com`)"
        - "traefik.http.middlewares.nforwardauth.forwardauth.address=http://nforwardauth:3000"
        - "traefik.http.services.nforwardauth.loadbalancer.server.port=3000"
      volumes:
        - "/path/to/passwd:/passwd:ro" # Mount local passwd file at /passwd as ready only

    whoami: # whoami example container accessible at "whoami.localhost.com" behind nforwardauth middleware
      image: traefik/whoami
      labels:
        - "traefik.http.routers.whoami.rule=Host(`whoami.localhost.com`)"
        - "traefik.http.routers.whoami.middlewares=nforwardauth"
  ```

</details>

#### Available Evironment Variables

***bold** variables are required*
| Variable | Description | Type | Default | Example |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| **`AUTH_HOST`** | **URL where nforwardauth is accessible** | **string** | **N/A** | **`nforwardauth.yourdomain.com`**
| **`TOKEN_SECRET`** | **Secret to use when signing the auth token** | **string** | **N/A** | **`example_secret_123`**
| `COOKIE_SECURE` | Whether or not to set cookies with secure flag | boolean | `true` | `false`
| `COOKIE_DOMAIN` | Set the domain for the cookies, allow auth on sites beyond the root domain | string | Inferred by base url of `AUTH_HOST` | `mydomain.com`
| `COOKIE_NAME` | Set name for the cookies. Helpful if running multiple instances to prevent collision | string | `nforwardauth` | `auth-token-1`
| `PORT` | Set port to litsen on | number | `3000` | `80`

## Roadmap

Here are some current todo's for the project:

- Find and fix bugs
- Add CRSF token/cookie for protection
- Better documentation and examples
- Add built-in themes for login page
- Documentation on how to write your own login page and mount at `/public` on the container
- Improved error handling and logging
- Futher integrations with proxies, loadbalancers, and homepage applications

If you have a suggestion or feature, please feel free to submit an issue and influence the list.

## Contributing

If you find a bug or have a suggestion for how to improve nforwardauth or additional functionality, please feel free to submit an issue or a pull request. We welcome contributions from the community and are committed to making nforwardauth as useful as possible for everyone who uses it.

## License

nforwardauth is released under the MIT license. please see the [LICENSE](https://giuthub.com/nosduco/nforwardauth/blob/main/license.md) file for details.

