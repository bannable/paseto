ARG DISTRO="jammy"
FROM mcr.microsoft.com/devcontainers/base:${DISTRO}

ARG SODIUM="libsodium23"
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends ${SODIUM} watchman \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode

RUN mkdir -p /home/$USERNAME/.vscode-server/extensions \
        /home/$USERNAME/.vscode-server-insiders/extensions \
        && chown -R $USERNAME \
        /home/$USERNAME/.vscode-server \
        /home/$USERNAME/.vscode-server-insiders \
        && gpg --keyserver keyserver.ubuntu.com --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
