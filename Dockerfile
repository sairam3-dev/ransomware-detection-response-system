
FROM python:3.13-slim

WORKDIR /app
ENV PYTHONPATH=/app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV RDRS_DATABASE_PATH=/app/data/rdrs.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config.yaml .

RUN mkdir -p /app/data/sandbox /app/data/quarantine /app/logs /app/reports

EXPOSE 8081

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
