FROM node:24-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Europe/Paris \
    LANG=fr_FR.UTF-8 \
    LANGUAGE=fr_FR:fr \
    LC_ALL=fr_FR.UTF-8 \
    NODE_ENV=production \
    BASE_LOGIN_METHOD=true \
    LOG_LEVEL=info

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        locales \
        openssh-client \
        ca-certificates \
        bash \
        tzdata \
    && sed -i '/fr_FR.UTF-8/s/^# //' /etc/locale.gen \
    && locale-gen \
    && ln -snf /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TZ}" > /etc/timezone \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts

COPY package.json ./
COPY startup.sh ./
COPY src ./src

RUN chmod +x /scripts/startup.sh \
    && npm install --omit=dev --ignore-scripts=false \
    && chown -R node:node /scripts

EXPOSE 3000

USER node

CMD ["/bin/bash", "/scripts/startup.sh"]
