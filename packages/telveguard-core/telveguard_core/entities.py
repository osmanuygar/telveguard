"""
Varlık adı eşleştirme: politika, maskeleme ve eklenti listeleri joker karakter destekler.

    entity_in: [TCKN, "SECRET_*"]   -> TCKN ve tüm sır türleri
"""
from fnmatch import fnmatchcase
from typing import Iterable, Set


def entity_matches(entity: str, patterns: Iterable[str]) -> bool:
    return any(fnmatchcase(entity, p) for p in patterns)


def matching_entities(entities: Iterable[str], patterns: Iterable[str]) -> Set[str]:
    patterns = list(patterns)
    return {e for e in entities if entity_matches(e, patterns)}
