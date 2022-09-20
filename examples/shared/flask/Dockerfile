FROM python:3.10.7-slim-bullseye@sha256:6de22c9cf887098265b7614582b00641c0c8c6735af538d0f267d6bb457634f1

ADD requirements.txt /tmp/flask-requirements.txt
RUN pip3 install -qr /tmp/flask-requirements.txt
RUN mkdir /code

ENTRYPOINT ["python3", "/code/service.py"]
