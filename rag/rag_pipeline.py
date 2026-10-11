from rag.retriever import retrieve


def build_rag_context(query: str, top_k: int = 3) -> dict:
    """
    Recherche les passages pertinents et prépare le contexte
    à transmettre plus tard à un agent IA.
    """
    results = retrieve(query, top_k=top_k)

    if not results:
        return {
            "query": query,
            "results": [],
            "context": "Aucun passage pertinent trouvé dans la base documentaire.",
        }

    context_parts = []

    for index, result in enumerate(results, start=1):
        context_parts.append(
            f"[Source {index}: {result['source']}]\n"
            f"[Score BM25: {result['score']}]\n"
            f"{result['text']}"
        )

    return {
        "query": query,
        "results": results,
        "context": "\n\n".join(context_parts),
    }
