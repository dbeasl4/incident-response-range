FROM python:3.11-slim
WORKDIR /app
COPY proxy.py .
# No external dependencies -- uses only stdlib
CMD ["python3", "proxy.py"]
