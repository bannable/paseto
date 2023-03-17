ARG VARIANT="3-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/ruby:0-${VARIANT}

ARG SODIUM="libsodium23"
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends ${SODIUM} watchman \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode

RUN mkdir -p /home/$USERNAME/.vscode-server/extensions \
        /home/$USERNAME/.vscode-server-insiders/extensions \
        && chown -R $USERNAME \
        /home/$USERNAME/.vscode-server \
        /home/$USERNAME/.vscode-server-insiders