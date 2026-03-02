import pickle, numpy as np
import scipy.sparse as sp
import re, os
from features.extractor import extract_features, SQL, XSS, RCE, LFI, CMD

BLOCK_THRESHOLD  = float(os.getenv("CONFIDENCE_THRESHOLD", 0.75))
BYPASS_THRESHOLD = float(os.getenv("BYPASS_FLAG_THRESHOLD", 0.40))

class InferenceEngine:
    def __init__(self, version="v1"):
        base = os.path.dirname(__file__)
        with open(f"{base}/models/model_{version}.pkl", "rb") as f:
            self.model = pickle.load(f)
        with open(f"{base}/models/tfidf_{version}.pkl", "rb") as f:
            self.tfidf = pickle.load(f)
        self.version = version

    def predict(self, payload: str) -> dict:
        tfidf_vec = self.tfidf.transform([payload])
        num_vec   = np.array([list(extract_features(payload).values())])
        X         = sp.hstack([tfidf_vec, sp.csr_matrix(num_vec)])

        proba      = self.model.predict_proba(X)[0]
        p_mal      = float(proba[1])

        if p_mal >= BLOCK_THRESHOLD:
            decision = "BLOCK"
        elif p_mal >= BYPASS_THRESHOLD:
            decision = "BYPASS_SUSPECT"
        else:
            decision = "ALLOW"

        return {
            "decision":     decision,
            "confidence":   round(p_mal, 4),
            "attack_type":  self._attack_type(payload),
            "model_version": self.version,
        }

    def _attack_type(self, p) -> str:
        if SQL.search(p): return "SQLi"
        if XSS.search(p): return "XSS"
        if RCE.search(p): return "RCE"
        if LFI.search(p): return "LFI"
        if CMD.search(p): return "CMDi"
        return "Unknown"