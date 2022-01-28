# syntax=docker/dockerfile:1

FROM node:10.12.0-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY ["package.json", "package-lock.json*", "appng.js", "./"]
RUN npm install --$NODE_ENV

COPY . . 
ENTRYPOINT [ "node", "appng.js" ]
