#!/usr/bin/env bash
# İnternete çıkabilen bir makinede çalıştırın; ./models dizinini imaja/PVC'ye taşıyın.
# Böylece gateway çalışma anında HuggingFace'e hiç bağlanmaz (KVKK + güvenlik).
set -euo pipefail
pip install -q "huggingface_hub[cli]"
mkdir -p models

# Türkçe NER (PER/LOC/ORG) - lisansını kurum içi kullanım için kontrol edin
huggingface-cli download akdeniz27/bert-base-turkish-cased-ner --local-dir models/tr-ner

# LLM Guard'ın varsayılan prompt injection modeli
huggingface-cli download protectai/deberta-v3-base-prompt-injection-v2 --local-dir models/prompt-injection

# Harbor'a OCI artifact olarak itmek isterseniz (oras):
# oras push harbor.sirket.local/telveguard/models:tr-ner-v1 models/tr-ner
echo "Modeller ./models altına indirildi."
