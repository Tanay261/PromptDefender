from __future__ import annotations
import logging
import re, math, pathlib, json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Tuple
from importlib.resources import files
import yaml
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

HEUR_PATH = files("promptdefender").joinpath("heuristics.yaml")
ATTACK_BANK_PATH = files("promptdefender").joinpath("assets/attack_bank.txt")

with open(HEUR_PATH, "r", encoding="utf-8") as f:
    heur_cfg = yaml.safe_load(f)

attacks = ATTACK_BANK_PATH.read_text(encoding="utf-8").splitlines()

@dataclass
class Explanation:
    source: str     # "heuristic" or "semantic"
    id: str
    label: str
    score: float
    detail: str

@dataclass
class DetectionResult:
    risk_score: float
    labels: List[str]
    decision: str   # "ALLOW" | "SANITIZE" | "DENY"
    explanations: List[Explanation]
    sanitized_prompt: str | None = None

class HeuristicEngine:
    def __init__(self, config: Dict[str, Any]):
        self.rules = []
        for r in config["rules"]:
            compiled = [re.compile(p) for p in r["patterns"]]
            self.rules.append({**r, "compiled": compiled})
        self.thresholds = config.get("thresholds", {})
    def score(self, text: str) -> Tuple[float, List[Explanation], List[str]]:
        total = 0.0
        expl: List[Explanation] = []
        labels: List[str] = []
        for r in self.rules:
            hits = sum(1 for rx in r["compiled"] if rx.search(text))
            if hits:
                total += r["weight"]
                labels.append(r["label"])
                expl.append(Explanation(
                    source="heuristic",
                    id=r["id"],
                    label=r["label"],
                    score=float(r["weight"]),
                    detail=f"Matched {hits} pattern(s) in rule {r['id']}"
                ))
        return total, expl, list(sorted(set(labels)))

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_IMPL = "sbert"
except Exception:
    EMBEDDING_IMPL = "tfidf"

# If TF-IDF fallback is used:
from sklearn.feature_extraction.text import TfidfVectorizer

logger = logging.getLogger(__name__)

class SemanticEngine:

    def __init__(self, attack_texts: List[str], n_neighbors: int = 2, model_name: str = "all-MiniLM-L6-v2"):
        import logging, numpy as np
        from sklearn.neighbors import NearestNeighbors
        from sklearn.feature_extraction.text import TfidfVectorizer

        log = logging.getLogger(__name__)

        self.attack_texts = [t.strip() for t in attack_texts if t.strip()]
        self.n_neighbors = min(max(1, n_neighbors), max(1, len(self.attack_texts)))
        self.model = None  # default

        if EMBEDDING_IMPL == "sbert":
            try:
                from sentence_transformers import SentenceTransformer
                log.info("Loading SBERT model: %s", model_name)
                self.model = SentenceTransformer(model_name)                        # <-- must be non-None
                emb = self.model.encode(self.attack_texts, show_progress_bar=False,
                                    convert_to_numpy=True).astype(np.float32)
                norms = np.linalg.norm(emb, axis=1, keepdims=True); norms[norms==0] = 1.0
                self.attack_embs = emb / norms
                self.nn = NearestNeighbors(n_neighbors=self.n_neighbors, metric="cosine")
                self.nn.fit(self.attack_embs)
                self.mode = "sbert"
                log.info("SBERT ready: vecs=%d dim=%d", *self.attack_embs.shape)
                return
            except Exception as e:
                log.exception("SBERT init failed; falling back to TF-IDF: %s", e)
                self.model = None  # be explicit

        # --- TF-IDF fallback ---
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=8000)
        self.attack_vecs = self.vectorizer.fit_transform(self.attack_texts)
        self.nn = NearestNeighbors(n_neighbors=self.n_neighbors, metric="cosine")
        self.nn.fit(self.attack_vecs)
        self.mode = "tfidf"

    def _init_tfidf(self, attack_texts):
        # TF-IDF fallback
        self.vectorizer = TfidfVectorizer(ngram_range=(1,2), min_df=1, max_features=8000)
        self.attack_vecs = self.vectorizer.fit_transform(attack_texts)
        self.nn = NearestNeighbors(n_neighbors=self.n_neighbors, metric="cosine")
        self.nn.fit(self.attack_vecs)
        self.mode = "tfidf"
        logger.info("SemanticEngine: using TF-IDF fallback (local).")

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        # a, b should be 1D normalized vectors; fallback safe-handling
        if np.linalg.norm(a) == 0 or np.linalg.norm(b) == 0:
            return 0.0
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    def score(self, text: str) -> Tuple[float, List[Explanation], List[str]]:
        """
        Returns (score: float up to 40, explanations, labels)
        - When using embeddings, similarity -> score
        - When TF-IDF, use previous TF-IDF logic
        """
        if not text or not text.strip():
            return 0.0, [], []

        if self.mode == "sbert":
            try:
                q_emb = self.model.encode([text], show_progress_bar=False, convert_to_numpy=True)
                q_emb = q_emb.astype(np.float32)
                qnorm = np.linalg.norm(q_emb, axis=1, keepdims=True)
                qnorm[qnorm == 0] = 1.0
                q_emb = q_emb / qnorm
                dists, idxs = self.nn.kneighbors(q_emb, n_neighbors=self.n_neighbors)
                # cosine distance -> similarity
                sim = 1.0 - float(dists[0][0])
                score = max(0.0, sim) * 40.0  # up to 40 contribution
                nearest = self.attack_texts[idxs[0][0]]
                expl = [Explanation(
                    source="semantic",
                    id="EMB_ATTACK_SIM",
                    label="attack-similarity",
                    score=float(score),
                    detail=f"Nearest exemplar sim={sim:.3f}: {nearest[:160]}"
                )]
                labels = ["attack-similarity"] if score >= 10 else []
                return score, expl, labels
            except Exception as e:
                # If anything goes wrong, degrade gracefully to TF-IDF fallback if available
                logger.exception("SemanticEngine: embedding scoring failed (%s). Falling back to TF-IDF for this query.", e)
                if hasattr(self, "vectorizer"):
                    q = self.vectorizer.transform([text])
                    dists, idxs = self.nn.kneighbors(q, n_neighbors=self.n_neighbors)
                    sim = 1.0 - float(dists[0][0])
                    score = max(0.0, sim) * 40.0
                    nearest = self.attack_texts[idxs[0][0]]
                    expl = [Explanation(
                        source="semantic",
                        id="KNN_ATTACK_SIM_TFIDF",
                        label="attack-similarity",
                        score=float(score),
                        detail=f"Nearest exemplar sim={sim:.3f}: {nearest[:160]}"
                    )]
                    labels = ["attack-similarity"] if score >= 10 else []
                    return score, expl, labels
                return 0.0, [], []
        else:
            # TF-IDF path (existing behavior)
            q = self.vectorizer.transform([text])
            dists, idxs = self.nn.kneighbors(q, n_neighbors=self.n_neighbors)
            sim = 1.0 - float(dists[0][0])
            score = max(0.0, sim) * 40.0
            nearest = self.attack_texts[idxs[0][0]]
            expl = [Explanation(
                source="semantic",
                id="KNN_ATTACK_SIM",
                label="attack-similarity",
                score=float(score),
                detail=f"Nearest exemplar sim={sim:.3f}: {nearest[:160]}"
            )]
            labels = ["attack-similarity"] if score >= 10 else []
            return score, expl, labels

class Detector:
    def __init__(self):
        with open(HEUR_PATH, "r", encoding="utf-8") as f:
            heur_cfg = yaml.safe_load(f)
        self.heur = HeuristicEngine(heur_cfg)
        with open(ATTACK_BANK_PATH, "r", encoding="utf-8") as f:
            attacks = f.readlines()
        self.sem = SemanticEngine(attacks)
        self.thresholds = self.heur.thresholds

    def analyze(self, prompt: str) -> DetectionResult:
        h_score, h_expl, h_labels = self.heur.score(prompt)
        s_score, s_expl, s_labels = self.sem.score(prompt)
        risk = min(100.0, h_score + s_score)
        labels = sorted(set(h_labels + s_labels))
        decision = "ALLOW"
        if risk >= self.thresholds.get("deny", 60):
            decision = "DENY"
        elif risk >= self.thresholds.get("sanitize", 30):
            decision = "SANITIZE"
        return DetectionResult(
            risk_score=round(risk, 1),
            labels=labels,
            decision=decision,
            explanations=h_expl + s_expl
        )
