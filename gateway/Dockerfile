# Air-gapped ortamda base imajı Harbor proxy-cache'ten çekin:
#   FROM harbor.sirket.local/dockerhub-proxy/library/python:3.12-slim
FROM python:3.12-slim
# Ek tarama: görsel / taranmış PDF için OCR (Türkçe + İngilizce). Air-gapped ortamda apt
# deposunu iç aynadan (Nexus / Artifactory) kullanın.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-tur tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY packages/telveguard-core /tmp/telveguard-core
COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt /tmp/telveguard-core
COPY gateway/app ./app
COPY gateway/entrypoint.sh ./entrypoint.sh
RUN chmod 0555 ./entrypoint.sh
# OpenShift rastgele UID ile çalıştırır: root'a ihtiyaç yok, grup 0 yazılabilir
RUN chgrp -R 0 /srv && chmod -R g=u /srv
USER 1001
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
EXPOSE 8080
# WORKERS: pod başına uvicorn worker sayısı (metrikler worker'lar arası birleştirilir)
ENV WORKERS=2
CMD ["./entrypoint.sh"]
