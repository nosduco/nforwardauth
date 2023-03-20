traefik-up: 
  docker-compose --file ./examples/traefik-v2/docker-compose.yml up

traefik-build:
  docker-compose --file ./examples/traefik-v2/docker-compose.yml build

traefik-down:
  docker-compose --file ./examples/traefik-v2/docker-compose.yml down

caddy-up: 
  docker-compose --file ./examples/caddy-v2//docker-compose.yml up

caddy-build:
  docker-compose --file ./examples/caddy-v2/docker-compose.yml build

caddy-down:
  docker-compose --file ./examples/caddy-v2/docker-compose.yml down

docs:
  cargo doc --open
