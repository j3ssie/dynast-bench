FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN --mount=type=cache,target=/root/.npm npm install --omit=dev
COPY . .
ENV PORT=3000 LLM_BACKEND=stub
EXPOSE 3000
CMD ["node","src/app.mjs"]
