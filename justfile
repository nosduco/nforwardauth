up: 
  docker-compose --file ./examples/traefik-v2/docker-compose.yml up

up-build:
  docker-compose --file ./examples/traefik-v2/docker-compose.yml build
  docker-compose --file ./examples/traefik-v2/docker-compose.yml up

down:
  docker-compose --file ./examples/traefik-v2/docker-compose.yml down

docs:
  cargo doc --open
