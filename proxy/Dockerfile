FROM registry.access.redhat.com/ubi9/nodejs-22

WORKDIR /opt/app-root/src

COPY --chown=1001:0 package.json ./
RUN npm install --production

COPY --chown=1001:0 server.js ./
COPY --chown=1001:0 public/ ./public/

ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
