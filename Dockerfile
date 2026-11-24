FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY server.js ./
COPY public ./public
COPY test_files ./test_files

RUN mkdir -p uploads/vulnerable uploads/secure

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
