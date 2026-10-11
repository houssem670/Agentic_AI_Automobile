import math
import re
from pathlib import Path
from collections import Counter

DOCUMENTS_DIR = Path(__file__).parent / "documents"

# Mots courants sans grande valeur pour la recherche.
STOP_WORDS = {
    # Français
    "le", "la", "les", "un", "une", "des", "du", "de", "d",
    "dans", "en", "et", "ou", "à", "au", "aux", "pour",
    "par", "avec", "sur", "comment", "quel", "quelle",
    "quels", "quelles", "est", "sont", "entre", "ce", "ces",
    "qui", "que", "quoi", "son", "sa", "ses", "se", "pas",
    "plus", "comme", "il", "elle", "leur", "leurs",

    # Anglais
    "the", "a", "an", "of", "and", "or", "in", "on",
    "for", "to", "is", "are", "how", "what", "which",
    "does", "do", "with", "from", "by", "that", "this",
    "these", "those", "it", "its", "be", "as",
}


def tokenize(text: str) -> list[str]:
    """Transforme un texte en termes utiles pour la recherche."""
    words = re.findall(r"\b[a-zA-ZÀ-ÿ0-9_]+\b", text.lower())
    return [word for word in words if word not in STOP_WORDS]

# Équivalences français-anglais adaptées à la recherche automobile.
QUERY_EXPANSIONS = {
    "bus can": "can bus controller area network",
    "attaque replay": "replay attack recorded messages retransmission",
    "replay": "replay attack repeated frames retransmission",
    "can flooding": "can flooding attack high message rate traffic volume",
    "flooding": "flooding attack high message rate traffic volume",
    "faux positifs": "false positives false positive false alarm",
    "faux négatifs": "false negatives false negative",
    "ids": "intrusion detection system intrusion detection",
    "obd-ii": "obd ii diagnostic trouble codes dtc",
    "uds": "unified diagnostic services iso 14229",
    "iso 21434": "cybersecurity engineering automotive cybersecurity",
    "iso 26262": "functional safety electrical electronic systems",
    "fréquence": "frequency message rate",
    "trames": "frames messages",
    "identifiants": "identifiers",
        # Usurpation d'identité et spoofing CAN
    "usurpation d'identifiant can":
        "spoofing attack forged identifier ECU impersonation",
    "usurpation": "spoofing attack forged identity impersonation",

    # Fréquence anormale et trafic légitime
    "hausse de fréquence can":
        "increased message rate frequency flooding legitimate traffic normal baseline",
    "ne prouve-t-elle pas une attaque":
        "does not prove attack legitimate operating conditions normal traffic false positive",
}


def expand_query(query: str) -> str:
    """Ajoute des termes anglais pour améliorer la recherche bilingue."""
    normalized_query = query.lower()
    expansions = []

    for phrase, related_terms in QUERY_EXPANSIONS.items():
        if phrase in normalized_query:
            expansions.append(related_terms)

    return " ".join([query, *expansions])


def is_boilerplate(section: str) -> bool:
    """Ignore les passages contenant uniquement des métadonnées."""
    lines = [
        line.strip().lower()
        for line in section.splitlines()
        if line.strip()
    ]

    if not lines:
        return True

    # Ignore les notes de source.
    if lines[0].startswith("source note:"):
        return True

    metadata_prefixes = (
        "title:",
        "domain:",
        "purpose:",
        "subject:",
        "sujet:",
    )

    # Ignore un passage composé uniquement de métadonnées.
    if all(line.startswith(metadata_prefixes) for line in lines):
        return True

    return False


def load_chunks() -> list[dict]:
    """Charge les fichiers et les découpe en passages."""
    chunks = []

    if not DOCUMENTS_DIR.exists():
        return chunks

    for path in sorted(DOCUMENTS_DIR.glob("*.txt")):
        text = path.read_text(encoding="utf-8")
        sections = re.split(r"\n\s*\n", text)

        for index, section in enumerate(sections, start=1):
            section = section.strip()

            if not section or is_boilerplate(section):
                continue

            terms = tokenize(section)

            if not terms:
                continue

            chunks.append({
                "source": path.name,
                "chunk_id": index,
                "text": section,
                "terms": terms,
                "frequencies": Counter(terms),
            })

    return chunks


def retrieve(query: str, top_k: int = 3) -> list[dict]:
    """Retourne les passages les plus pertinents avec BM25."""
    query_terms = tokenize(expand_query(query))

    if not query_terms or top_k <= 0:
        return []

    chunks = load_chunks()

    if not chunks:
        return []

    average_length = (
        sum(len(chunk["terms"]) for chunk in chunks) / len(chunks)
    )

    document_count = len(chunks)
    document_frequency = Counter()

    # Nombre de passages contenant chaque terme.
    for chunk in chunks:
        document_frequency.update(set(chunk["terms"]))

    results = []
    k1 = 1.5
    b = 0.75

    for chunk in chunks:
        score = 0.0
        frequencies = chunk["frequencies"]
        length = len(chunk["terms"])

        for term in set(query_terms):
            term_frequency = frequencies[term]

            if term_frequency == 0:
                continue

            df = document_frequency[term]

            inverse_frequency = math.log(
                1 + (document_count - df + 0.5) / (df + 0.5)
            )

            denominator = term_frequency + k1 * (
                1 - b + b * length / average_length
            )

            score += inverse_frequency * (
                term_frequency * (k1 + 1) / denominator
            )

        if score > 0:
            results.append({
                "source": chunk["source"],
                "chunk_id": chunk["chunk_id"],
                "score": round(score, 3),
                "text": chunk["text"],
            })

    return sorted(
        results,
        key=lambda item: item["score"],
        reverse=True,
    )[:top_k]
