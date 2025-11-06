FROM golang:1.25

ARG DEBIAN_FRONTEND=noninteractive

USER root
WORKDIR /root

RUN apt update && apt install -y \
  apt-transport-https ca-certificates gnupg lsb-release iputils-ping net-tools \
  curl wget git zip unzip less zsh jq lsof build-essential docker.io \
  && apt clean && rm -rf /var/lib/apt/lists/*

ENV HOME="/root"
# Required for some cgo operations such as using certain database drivers like SQLite
ENV CGO_ENABLED=1

# --------------------------------------
# Git
# --------------------------------------
# Need to add the devcontainer workspace folder as a safe directory to enable git 
# version control system to be enabled in the containers file system.
RUN git config --global --add safe.directory "/workspaces/go-better-auth"
# --------------------------------------

# --------------------------------------
# Oh my zsh
# --------------------------------------
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" -- \
  -t robbyrussell \
  -p git -p node -p npm

ENV SHELL=/bin/zsh
# --------------------------------------

# --------------------------------------
# Go tools
# --------------------------------------
# Install Go tools useful for dev
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest \
&& go install github.com/go-delve/delve/cmd/dlv@latest \
&& go install golang.org/x/tools/gopls@latest
# --------------------------------------

# --------------------------------------
# SSH 
# --------------------------------------
RUN mkdir -p ~/.ssh
RUN touch ~/.ssh/config
RUN echo "Host github.com" >> ~/.ssh/config \
  && echo "    IdentityFile ~/.ssh/id_ed25519" >> ~/.ssh/config
RUN touch ~/.ssh/id_ed25519
# --------------------------------------
