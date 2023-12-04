FROM python:3.11.5-alpine3.18

ENV PYTHONUNBUFFERED 1
ENV TRANSFORMERS_CACHE /app/hr_cache

# Copy necessary files to the container
COPY ./requirements/production.txt /requirements.txt
COPY ./app /app
COPY ./scripts /scripts

WORKDIR /app

EXPOSE 8000

RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    apk update && \
    apk add --no-cache postgresql-client build-base postgresql-dev linux-headers && \
    /py/bin/pip install -r /requirements.txt --use-pep517 && \
    adduser --disabled-password --gecos '' djuser && \
    mkdir -p /app/vol/static /app/vol/media && \
    chown -R djuser:djuser /app && \
    chmod -R 755 /app && \
    mkdir -p /app/hr_cache && \
    chown -R djuser:djuser /app/hr_cache


ENV PATH="/scripts:/py/bin:$PATH"


USER djuser


CMD ["run.sh"]
