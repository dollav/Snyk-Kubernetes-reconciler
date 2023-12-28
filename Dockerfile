FROM --platform=linux/amd64 python:latest

ENV PYTHONUNBUFFERED=1

WORKDIR /usr/app/sec

COPY . ./

RUN pip install --no-cache-dir --upgrade pip && \ 
    pip install --no-cache-dir requests kubernetes



COPY --from=snyk/snyk:linux /usr/local/bin/snyk /usr/local/bin/snyk

CMD ["python", "main.py"]