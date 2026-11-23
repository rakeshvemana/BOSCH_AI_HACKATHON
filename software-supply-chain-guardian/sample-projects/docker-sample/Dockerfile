# Multi-stage sample used for Dockerfile METADATA analysis (never built or run).
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim AS builder
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get update && apt-get install -y --no-install-recommends curl=7.88.1-10 git

FROM node:20-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS assets
COPY package.json package-lock.json ./
RUN apk add --no-cache bash

FROM nginx:latest
COPY --from=builder /app /usr/share/nginx/html
COPY ./static /usr/share/nginx/static
EXPOSE 80 443
USER nginx
