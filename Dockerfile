FROM python:3.13.5-alpine3.22

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TZ=Africa/Nairobi
ENV PYTHONPATH=/opt/bitrixprobe

WORKDIR /opt/bitrixprobe

RUN apk add --no-cache \
        ca-certificates \
        libffi \
        libpcap \
        openssl \
        tzdata \
    && cp /usr/share/zoneinfo/Africa/Nairobi /etc/localtime \
    && echo "Africa/Nairobi" > /etc/timezone

COPY ./requirements.txt .

RUN apk add --no-cache --virtual .build-deps \
        build-base \
        cargo \
        libffi-dev \
        linux-headers \
        openssl-dev \
        python3-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY bitrixprobe ./bitrixprobe

RUN addgroup -S bitrixprobe \
    && adduser -S -G bitrixprobe -h /home/bitrixprobe bitrixprobe \
    && mkdir -p /app/reports \
    && chown -R bitrixprobe:bitrixprobe /opt/bitrixprobe /app

WORKDIR /app

USER bitrixprobe

ENTRYPOINT ["python", "-m", "bitrixprobe"]
CMD ["--help"]
