ARG DISTRO="bullseye"
FROM mcr.microsoft.com/devcontainers/base:${DISTRO}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends libsodium23 \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode

RUN mkdir -p /home/$USERNAME/.vscode-server/extensions \
        /home/$USERNAME/.vscode-server-insiders/extensions \
        && chown -R $USERNAME \
        /home/$USERNAME/.vscode-server \
        /home/$USERNAME/.vscode-server-insiders
