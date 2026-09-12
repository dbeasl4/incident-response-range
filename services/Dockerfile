FROM python:3.11-slim
WORKDIR /app
RUN pip install flask --quiet
COPY internal_api.py .
COPY external_drop.py .
