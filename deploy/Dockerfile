# A decoy accepts hostile input by design, so it is the process on the network
# most likely to be talking to someone who wants it. The container is built on
# the assumption that the code in it will one day lose.
#
# Every line below removes something rather than adding it.

FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --target /install .


FROM python:3.12-slim

# A numeric, unprivileged, non-login account with no shell. If the process is
# taken, it is taken as somebody who cannot log in anywhere.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin decoy

COPY --from=build /install /usr/local/lib/python3.12/site-packages

# The one writable path, and it is a mount rather than part of the image. The
# root filesystem is read-only at runtime (see compose), so a write anywhere
# else fails rather than persisting.
RUN mkdir -p /captures && chown 10001:10001 /captures
VOLUME ["/captures"]

USER 10001:10001
WORKDIR /captures

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Unprivileged ports only. Binding 22 or 80 inside the container would need
# CAP_NET_BIND_SERVICE; the host maps the real ports instead, so the decoy
# never holds a capability it could lose.
EXPOSE 2222 8080 8081

ENTRYPOINT ["python", "-m", "decoy.cli"]
CMD ["run", "--log", "/captures/live.jsonl", \
     "--benign", "10.20.30.=internal vulnerability scanner subnet"]
