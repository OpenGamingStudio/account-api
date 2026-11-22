# Étape 1 : CSS Tailwind
FROM node:22-bookworm-slim AS css
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src/styles.css src/styles.css
COPY public public
RUN npx tailwindcss -i src/styles.css -o public/styles.css --minify

# Étape 2 : serveur (Node + SQLite). La base vit dans /data : monter un volume persistant dessus.
FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=80 DB_FILE=/data/account.db COOKIE_DOMAIN=.opengamingstudio.com
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src src
COPY public public
COPY --from=css /app/public/styles.css public/styles.css
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
VOLUME /data
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:80/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
