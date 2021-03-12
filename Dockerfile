FROM python:3-alpine

WORKDIR /app

RUN apk add build-base curl-dev libcurl libressl-dev

COPY dependabot dependabot
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

ENTRYPOINT [ "python3", "/app/dependabot/__main__.py" ]
