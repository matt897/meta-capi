FROM node:20-alpine AS deps
WORKDIR /app
COPY app/package.json ./
RUN npm install --production

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY app/ ./
EXPOSE 3000
CMD ["node", "server.js"]
