FROM node:24-bookworm-slim AS frontend
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.ts tsconfig.json postcss.config.js tailwind.config.js ./
COPY src ./src
COPY public ./public
RUN npm run build

FROM python:3.13-slim-bookworm
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERGUARD_SECURE_COOKIE=1
COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt
COPY backend ./backend
COPY --from=frontend /app/dist ./dist
CMD ["sh", "-c", "exec python -m uvicorn backend.main:app --host 0.0.0.0 --port \"${PORT:-8000}\" --no-access-log"]
