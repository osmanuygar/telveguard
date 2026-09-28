"""
Opsiyonel: Telveguard'ın Türkçe kurallarını Microsoft Presidio'ya recognizer olarak takar.
Kendi Presidio kurulumu olan ekipler için (pip install presidio-analyzer).

    from presidio_analyzer import AnalyzerEngine
    from telveguard_core.pii.presidio_adapter import presidio_recognizers
    for r in presidio_recognizers(): analyzer.registry.add_recognizer(r)
"""
from typing import List

from .tr_recognizers import TR_RECOGNIZERS


def presidio_recognizers(language: str = "tr") -> List:
    from presidio_analyzer import Pattern, PatternRecognizer

    out = []
    for rec in TR_RECOGNIZERS:
        validator = rec.validator

        class _R(PatternRecognizer):
            def validate_result(self, pattern_text, _v=validator):
                return _v(pattern_text) if _v else None

        out.append(_R(supported_entity=rec.entity, supported_language=language,
                      patterns=[Pattern(rec.entity.lower(), rec.pattern.pattern, rec.score)],
                      global_regex_flags=rec.pattern.flags))
    return out
