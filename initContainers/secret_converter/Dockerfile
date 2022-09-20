FROM python:3.8-slim-buster

COPY *.py /
COPY requirements.txt /
RUN python -m pip install -r /requirements.txt

ENTRYPOINT ["python", "main.py"]

