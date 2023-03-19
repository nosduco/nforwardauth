up: 
  docker-compose --file ./examples/traefik-v2/docker-compose.yml up

build:
  docker-compose --file ./examples/traefik-v2/docker-compose.yml build

down:
  docker-compose --file ./examples/traefik-v2/docker-compose.yml down

docs:
  cargo doc --open
