# Multi Retrieval CRS base image (prepare phase)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    rsync \
    curl \
    ca-certificates \
    gnupg \
    software-properties-common \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Python 3.12 (deadsnakes PPA)
RUN add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.12 python3.12-venv python3.12-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12
RUN ln -sf /usr/bin/python3.12 /usr/bin/python3 \
    && ln -sf python3 /usr/bin/python

# Python dependencies for multi-retrieval agent. Major versions are bounded:
# langchain 1.0 dropped ChatLiteLLM from langchain-community, so an unpinned
# install silently breaks the agent's import.
RUN pip3 install \
    "langchain-core>=1.0,<2" \
    "langchain-litellm>=0.7,<1" \
    "langgraph>=1.0,<2" \
    "litellm>=1.90,<2" \
    "ast-grep-py>=0.39,<1" \
    "pydantic>=2.10,<3"

# Git config
RUN git config --global user.email "crs@oss-crs.dev" \
    && git config --global user.name "OSS-CRS Patcher" \
    && git config --global --add safe.directory '*'
