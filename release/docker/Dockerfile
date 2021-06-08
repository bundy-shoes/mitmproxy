FROM alpine:3.12

ENV LANG=en_US.UTF-8

ARG WHEEL_MITMPROXY
ARG WHEEL_BASENAME_MITMPROXY

ENV HOME /home/mitmproxy

COPY $WHEEL_MITMPROXY $HOME

# Add our user first to make sure the ID get assigned consistently,
# regardless of whatever dependencies get added.

RUN addgroup -S mitmproxy && adduser -S -G mitmproxy mitmproxy \
    && apk add --no-cache \
    su-exec \
    git \
    g++ \
    libffi \
    libffi-dev \
    libstdc++ \
    openssl \
    openssl-dev \
    python3 \
    python3-dev \
    && python3 -m ensurepip --upgrade \
    && pip3 install -U pip \
    && LDFLAGS=-L/lib pip3 install -U $HOME/${WHEEL_BASENAME_MITMPROXY} \
    && apk del --purge \
    git \
    g++ \
    libffi-dev \
    openssl-dev \
    python3-dev \
    && rm -rf ~/.cache/pip $HOME/${WHEEL_BASENAME_MITMPROXY}

VOLUME $HOME/.mitmproxy

# HACK: the security context of the injected pod could be run as any user, therefore
# all users must be able to write to the directory.
RUN chmod -R 777 $HOME/.mitmproxy/

COPY release/docker/docker-entrypoint.sh /usr/local/bin/

COPY . /usr/mitmproxy

WORKDIR /usr/mitmproxy

USER root

RUN pip3 install -e ".[dev]"

USER mitmproxy

EXPOSE 8080 8081

