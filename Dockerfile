FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY app ./app
COPY tests ./tests

ENV HOST=0.0.0.0 \
    PORT=8000 \
    DATA_DIR=/data

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --retries=12 --start-period=5s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'), timeout=3)" || exit 1

CMD ["python", "-m", "app.server"]
