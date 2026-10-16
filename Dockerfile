FROM python:3.12-slim
WORKDIR /app
COPY app.py ./app.py
COPY static ./static
ENV PORT=8000
ENV PAYNEXUS_DB=/data/paynexus.sqlite3
ENV COOKIE_SECURE=1
EXPOSE 8000
CMD ["python", "app.py"]
