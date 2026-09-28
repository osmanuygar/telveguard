"""
Türkçe NER (kişi / kurum / yer) - opsiyonel, HuggingFace modeli LOKALDEN yüklenir.
Air-gapped: scripts/mirror_models.sh modeli indirir, TR_NER_MODEL_PATH ile verilir.
"""
import os
from typing import List, Optional, Tuple

LABEL_MAP = {"PER": "PERSON", "LOC": "LOCATION", "ORG": "ORGANIZATION"}


class TurkishNer:
    def __init__(self, model_path: Optional[str] = None, min_score: float = 0.85):
        self.model_path = model_path or os.getenv("TR_NER_MODEL_PATH", "/models/tr-ner")
        self.min_score = min_score
        self._pipe = None

    def _pipeline(self):
        if self._pipe is None:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            from transformers import pipeline

            self._pipe = pipeline("ner", model=self.model_path, tokenizer=self.model_path,
                                  aggregation_strategy="first")
        return self._pipe

    def analyze(self, text: str) -> List[Tuple[str, int, int, float]]:
        out = []
        for ent in self._pipeline()(text):
            label = LABEL_MAP.get(ent["entity_group"])
            if label and ent["score"] >= self.min_score:
                out.append((label, ent["start"], ent["end"], float(ent["score"])))
        return out
