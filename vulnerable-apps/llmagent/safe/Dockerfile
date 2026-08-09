FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
ENV PORT=3000 LLM_BACKEND=stub
EXPOSE 3000
CMD ["node","src/app.mjs"]
