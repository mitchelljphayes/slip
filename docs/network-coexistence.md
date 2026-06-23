# Network Coexistence with External Containers

slip creates a named Docker/Podman bridge network (default: `slip`) that all deployed containers join. This document explains how to connect external infrastructure (e.g., a separate compose stack for postgres, redis, etc.) to the slip network so containers can communicate.

## How slip's network works

When slipd starts, it creates a bridge network with `attachable: true`:

```
$ docker network ls | grep slip
slip     bridge    slip
```

All containers deployed by slip join this network automatically. Containers can resolve each other by container name (Docker/Podman built-in DNS).

## Connecting external infrastructure

For external containers (e.g., a compose stack running postgres, redis, rustfs) to communicate with slip-deployed containers, they need to join the same network.

### Docker Compose

```yaml
# docker-compose.infra.yml
services:
  postgres:
    image: postgres:16
    networks:
      - slip
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: statstream
      POSTGRES_USER: statstream
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}

  redis:
    image: redis:7
    networks:
      - slip

  rustfs:
    image: rustfs/rustfs:latest
    networks:
      - slip

networks:
  slip:
    external: true
    name: slip

volumes:
  postgres_data:
```

### Podman Compose

```yaml
# podman-compose.infra.yml
# Same structure as Docker Compose — podman-compose uses the same format
networks:
  slip:
    external: true
    name: slip
```

## DNS resolution

Containers on the same network resolve each other by service/container name:

- slip-deployed `api` container → reaches postgres at `postgres:5432`
- slip-deployed `dagster-daemon` → reaches redis at `redis:6379`
- External containers can reach slip-deployed containers by their container name

## Custom network name

To use a custom network name (e.g., if `slip` conflicts with another network):

```toml
# /etc/slip/slip.toml
[network]
name = "my-deploy-network"
```

Both slip and the external compose stack must reference the same network name.

## Verification

```bash
# Verify the network exists and is attachable
docker network inspect slip | jq '.[0].Attachable'
# → true

# Verify containers are on the network
docker network inspect slip | jq '.[0].Containers | keys'

# Test connectivity from a slip container
docker exec -it <slip-container> ping postgres
```

## Notes

- The `attachable: true` flag allows external containers to join the network after it's created
- slip creates the network on startup if it doesn't exist
- If you create the network manually before starting slipd, slip will detect it and skip creation
- Pod containers (via `podman kube play`) join the network specified in slip's config
- All containers on the network can resolve each other by name — no need for host port bindings