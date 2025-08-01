FROM node:lts-slim

RUN apt-get update \
    && apt-get install -y locales locales-all

COPY src /scripts/src
COPY startup.sh /scripts
COPY package.json /scripts

ENV LC_ALL=fr_FR.UTF-8
ENV LANG=fr_FR.UTF-8
ENV LANGUAGE=fr_FR.UTF-8
ENV BASE_LOGIN_METHOD=true
ENV LOG_LEVEL=info

WORKDIR /scripts

RUN npm install

EXPOSE 3000

USER node

CMD ["sh","-c", "./startup.sh"]
