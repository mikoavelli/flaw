import json
import math
import re
from pathlib import Path


class FlawPredictor:
    def __init__(self, model_path: str | Path):
        with open(model_path, encoding="utf-8") as f:
            self.data = json.load(f)

        self.features = self.data["features"]
        self.trees = self.data["trees"]

        self.vendor_vocab = self.data.get("vendor_vocab", [])
        self.product_vocab = self.data.get("product_vocab", [])
        self.cwe_vocab = self.data.get("cwe_vocab", [])
        self.desc_vocab = self.data.get("desc_vocab", [])
        self.desc_idf = self.data.get("desc_idf", [])

        self._v_map = {v: i for i, v in enumerate(self.vendor_vocab)}
        self._p_map = {p: i for i, p in enumerate(self.product_vocab)}
        self._cwe_map = {c: i for i, c in enumerate(self.cwe_vocab)}
        self._desc_map = {d: i for i, d in enumerate(self.desc_vocab)}

        self._word_pattern = re.compile(r"\b[a-zA-Z]{3,}\b")
        self._token_pattern = re.compile(r"[^\s]+")

    def _tokenize_words(self, text: str) -> list[str]:
        return self._word_pattern.findall(text.lower())

    def _tokenize_tokens(self, text: str) -> list[str]:
        return self._token_pattern.findall(text.lower())

    def extract_features(
        self,
        cvss_base: float,
        cvss_av: int,
        cvss_ac: int,
        cvss_pr: int,
        cvss_ui: int,
        cvss_s: int,
        cvss_c: int,
        cvss_i: int,
        cvss_a: int,
        vendors_str: str,
        products_str: str,
        cwe_str: str,
        description: str,
    ) -> list[float]:
        feature_vector = [0.0] * len(self.features)

        feature_vector[0] = float(cvss_base)
        feature_vector[1] = float(cvss_av)
        feature_vector[2] = float(cvss_ac)
        feature_vector[3] = float(cvss_pr)
        feature_vector[4] = float(cvss_ui)
        feature_vector[5] = float(cvss_s)
        feature_vector[6] = float(cvss_c)
        feature_vector[7] = float(cvss_i)
        feature_vector[8] = float(cvss_a)

        idx_offset = 9

        for token in set(self._tokenize_tokens(vendors_str)):
            if token in self._v_map:
                feature_vector[idx_offset + self._v_map[token]] = 1.0
        idx_offset += len(self.vendor_vocab)

        for token in set(self._tokenize_tokens(products_str)):
            if token in self._p_map:
                feature_vector[idx_offset + self._p_map[token]] = 1.0
        idx_offset += len(self.product_vocab)

        for token in set(self._tokenize_tokens(cwe_str)):
            if token in self._cwe_map:
                feature_vector[idx_offset + self._cwe_map[token]] = 1.0
        idx_offset += len(self.cwe_vocab)

        desc_tokens = self._tokenize_words(description)
        tf_counts = {}
        for token in desc_tokens:
            if token in self._desc_map:
                tf_counts[token] = tf_counts.get(token, 0) + 1

        tfidf_values = [0.0] * len(self.desc_vocab)
        sum_sq = 0.0

        for token, tf in tf_counts.items():
            vocab_idx = self._desc_map[token]
            idf = self.desc_idf[vocab_idx]
            val = tf * idf
            tfidf_values[vocab_idx] = val
            sum_sq += val * val

        if sum_sq > 0:
            norm = math.sqrt(sum_sq)
            for i in range(len(tfidf_values)):
                if tfidf_values[i] > 0:
                    feature_vector[idx_offset + i] = tfidf_values[i] / norm

        return feature_vector

    def _predict_tree(self, tree: dict, features: list[float]) -> float:
        node = tree
        while "leaf" not in node:
            split_idx = node["split"]
            split_cond = node["split_condition"]
            if features[split_idx] < split_cond:
                node = node["children"][0]
            else:
                node = node["children"][1]
        return node["leaf"]

    def predict_proba(self, features: list[float]) -> float:
        raw_sum = sum(self._predict_tree(tree, features) for tree in self.trees)
        return 1.0 / (1.0 + math.exp(-raw_sum))


def test_inference():
    model_path = Path(__file__).parent.parent / "data" / "models" / "xgboost_portable.json"

    if not model_path.exists():
        print(f"Model not found: {model_path}")
        return

    predictor = FlawPredictor(model_path)

    test_cases = [
        {
            "name": "Critical Windows RCE (High Risk)",
            "cvss": [9.8, 3, 1, 2, 1, 0, 2, 2, 2],
            "vendors": "microsoft",
            "products": "windows_10",
            "cwe": "cwe-94 cwe-20",
            "desc": "Remote Code Execution vulnerability in Microsoft \
                Windows 10 allows unauthenticated attackers to execute \
                    arbitrary code via malformed packets.",
        },
        {
            "name": "Low Severity WordPress Plugin XSS (Low Risk)",
            "cvss": [4.8, 3, 1, 1, 0, 1, 1, 1, 0],
            "vendors": "unknown_dev",
            "products": "some_wp_plugin",
            "cwe": "cwe-79",
            "desc": "Cross-site scripting (XSS) vulnerability in a \
                WordPress plugin allows authenticated users to inject arbitrary web scripts.",
        },
    ]

    for tc in test_cases:
        feats = predictor.extract_features(
            *tc["cvss"],
            vendors_str=tc["vendors"],
            products_str=tc["products"],
            cwe_str=tc["cwe"],
            description=tc["desc"],
        )
        score = predictor.predict_proba(feats)
        print(f"--- {tc['name']} ---")
        print(f"Probability of Exploitation (EPSS / KEV-like risk): {score * 100:.2f}%\n")


if __name__ == "__main__":
    test_inference()
