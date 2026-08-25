FROM python:3.14-alpine

RUN addgroup -S cicig \
    && adduser -S -G cicig cicig

WORKDIR /app
COPY panel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY panel/app.py .
COPY panel/templates ./templates
COPY panel/static ./static
COPY assets/cicig-cat-hacker.png ./static/cicig-cat.png
COPY assets/lucide.svg ./static/lucide.svg

EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "4", "--timeout", "600", "app:app"]
