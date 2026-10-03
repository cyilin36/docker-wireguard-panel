# syntax=docker/dockerfile:1

# --------------------------------------------------------------------------- #
# build stage: produce a wheel (no interpreter is copied between stages, so the
# runtime image cannot end up with a virtualenv pointing at a missing python)
# --------------------------------------------------------------------------- #
FROM python:3.12-alpine3.21 AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip wheel --no-cache-dir --wheel-dir /dist .

# --------------------------------------------------------------------------- #
# runtime stage
# --------------------------------------------------------------------------- #
# The panel shares the wireguard container's network namespace, so it needs the
# tools itself: wg-quick is a bash script, and the LinuxServer PostUp/PostDown
# hooks it executes call iptables/nft.
FROM python:3.12-alpine3.21

RUN apk add --no-cache \
        bash \
        ca-certificates \
        ip6tables \
        iproute2 \
        iptables \
        nftables \
        openresolv \
        tcpdump \
        tzdata \
        wireguard-tools \
 && rm -rf /var/cache/apk/*

# Every dependency was turned into a wheel above, so this install stays offline.
COPY --from=build /dist /dist
RUN pip install --no-cache-dir --no-index --find-links=/dist wgpanel \
 && rm -rf /dist

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WG_CONFIG_DIR=/config/wg_confs \
    WG_STATE_DIR=/config/.wgpanel \
    PANEL_PORT=47710

# The panel needs root: wg-quick drops privileges via sudo when it is not root,
# and the NET_ADMIN operations require it.
USER root

EXPOSE 47710

ENTRYPOINT ["wgpanel"]
CMD ["serve"]
