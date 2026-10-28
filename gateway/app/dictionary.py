"""Kurumsal sözlük telveguard-core'da (telveguard_core.dictionary): ContextForge eklentisi ve
`telve` de aynı ayrıştırmayı kullanır. Bu modül gateway içi import'lar için yeniden dışa aktarır."""
from telveguard_core.dictionary import *  # noqa: F401,F403
from telveguard_core.dictionary import (  # noqa: F401  (alt çizgili / __all__ dışı adlar)
    HASH_HEX, MAX_TERMS, PREFIX, Dictionary, DictionaryError, Entry, _fold, browser_payload, load,
    term_hash, trie_regex,
)
