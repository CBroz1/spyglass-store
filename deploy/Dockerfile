# Broker image. Small on purpose: this service holds the only credential that
# can write to the object store, so every package in it is attack surface.
#
# Note what is *not* installed. The broker never imports `spyglass`, so pynwb,
# spikeinterface, jax, and the numpy/scipy pins that come with them stay out.
# Keeping that stack away from a web service is the reason this is a separate
# repository, and this file is where that promise is kept or broken.
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --prefix=/install ".[serve]"


FROM python:3.12-slim

# Run unprivileged. A broker compromise should not also be a root shell.
RUN useradd --create-home --uid 10001 broker

COPY --from=build /install /usr/local

USER broker
WORKDIR /home/broker

EXPOSE 8000

# `--factory` because the app is built by `create_app()`, which takes its
# dependencies as arguments so tests can inject fakes.
#
# Startup verifies the bucket and the Spyglass lab schema before accepting
# traffic, so a container that stays up is one whose configuration was good.
CMD ["uvicorn", "spyglass_store.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
