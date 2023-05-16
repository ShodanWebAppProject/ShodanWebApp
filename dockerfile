# syntax=docker/dockerfile:1
# docker build --tag shodan/webserver .
# docker run --publish 5000:50505 shodan/webserver
# at port 127.0.0.1:5000

FROM python:3.11

WORKDIR /code

COPY requirements.txt .

RUN pip3 install -r requirements.txt

COPY . .

EXPOSE 50505 

ENTRYPOINT ["gunicorn", "app_server:app"]