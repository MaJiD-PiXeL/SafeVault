FROM node:24-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.14-slim AS backend
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn==26.2.0
COPY backend/ ./
COPY deploy/gunicorn.conf.py deploy/ready.py deploy/worker.sh /opt/safevault/
RUN DJANGO_SECRET_KEY=collectstatic-build-key python manage.py collectstatic --noinput \
    && groupadd --gid 10001 safevault \
    && useradd --uid 10001 --gid 10001 --no-create-home safevault \
    && install -d -m 0750 -o safevault -g safevault /run/safevault
USER 10001:10001
CMD ["gunicorn", "--config", "/opt/safevault/gunicorn.conf.py", "config.wsgi:application"]

FROM caddy:2.11-alpine AS edge
COPY --from=frontend /build/dist/ /srv/vault/
COPY --from=backend /app/staticfiles/ /srv/admin/
COPY deploy/Caddyfile /etc/caddy/Caddyfile
