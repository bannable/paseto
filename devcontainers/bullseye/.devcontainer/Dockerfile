# [Choice] Ruby version (use -bullseye variants on local arm64/Apple Silicon): 3, 3.1, 3.0, 2, 2.7, 3-bullseye, 3.1-bullseye, 3.0-bullseye, 2-bullseye, 2.7-bullseye, 3-buster, 3.1-buster, 3.0-buster, 2-buster, 2.7-buster
ARG VARIANT="3-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/ruby:0-${VARIANT}

ARG SODIUM="libsodium23"
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends ${SODIUM} \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode

RUN mkdir -p /home/$USERNAME/.vscode-server/extensions \
        /home/$USERNAME/.vscode-server-insiders/extensions \
        && chown -R $USERNAME \
        /home/$USERNAME/.vscode-server \
        /home/$USERNAME/.vscode-server-insiders
