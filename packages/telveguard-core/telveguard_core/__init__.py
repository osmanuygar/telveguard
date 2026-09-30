"""Telveguard çekirdek motoru: Türkçe PII, prompt injection, politika.

Hem Telveguard LLM Gateway'i hem de ContextForge eklentisi bu paketi kullanır;
tespit mantığı tek yerde yaşar.
"""
from .detectors.injection import InjectionDetector, InjectionResult
from .entities import entity_matches, matching_entities
from .pii.engine import Finding, MaskResult, TrPiiEngine
from .policy import Context, Decision, PolicyEngine

__all__ = ["TrPiiEngine", "Finding", "MaskResult", "InjectionDetector",
           "InjectionResult", "PolicyEngine", "Context", "Decision",
           "entity_matches", "matching_entities"]
__version__ = "0.2.1"
