FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements.lock

COPY app ./app
COPY scripts ./scripts

EXPOSE 8790

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8790", "--no-access-log", "--forwarded-allow-ips", "127.0.0.1"]
