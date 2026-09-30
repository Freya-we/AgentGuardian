"""ONNX 嵌入模型语义审查器 — 替代 RuleEngine 的场景2语义分析"""
import logging
import os
from pathlib import Path

import numpy as np

from src.engine.slm_baseline import get_embeddings_array

logger = logging.getLogger(__name__)

MODEL_PATH_DEFAULT = str(Path.home() / ".cache" / "agent-guardian" / "model.onnx")
TOKENIZER_DIR = str(Path.home() / ".cache" / "agent-guardian")
THRESHOLD_HIGH = 0.70
THRESHOLD_LOW = 0.45


class SlmReviewer:
    """基于 ONNX 嵌入的语义审查器

    若模型文件不存在 → is_available()=False, review() 返回中性分数
    """

    def __init__(self, model_path: str = MODEL_PATH_DEFAULT):
        self._model_path = model_path
        self._session = None
        self._tokenizer = None
        self._baseline = None
        self._available = False
        self._init_model()

    def _init_model(self) -> None:
        if not os.path.exists(self._model_path):
            logger.warning(
                "ONNX 模型不存在 (%s), 语义审查降级。运行 scripts/export_onnx_model.py 导出",
                self._model_path,
            )
            return
        try:
            import onnxruntime as ort
            from transformers import AutoTokenizer
            self._session = ort.InferenceSession(
                self._model_path,
                providers=["CPUExecutionProvider"],
            )
            self._tokenizer = AutoTokenizer.from_pretrained(
                TOKENIZER_DIR,
                local_files_only=True,
            )
            self._baseline = get_embeddings_array()
            if self._baseline.shape[0] == 0:
                logger.warning("基线嵌入为空，语义审查降级")
                return
            self._available = True
            logger.info("ONNX 模型已加载 (%s), 基线样本=%d",
                        os.path.basename(self._model_path), self._baseline.shape[0])
        except Exception as e:
            logger.error("ONNX 模型加载失败: %s", e)
            self._available = False

    async def review(self, content: str, context: str = "") -> tuple[float, str]:
        """返回 (risk_score, reason). score ∈ [0, 1]"""
        if not self._available or self._session is None:
            return (0.5, "slm_unavailable")

        # 空或极短内容直接放行
        if not content or len(content.strip()) < 8:
            return (0.1, "内容过短")

        try:
            embedding = self._encode(content)
        except Exception as e:
            logger.error("ONNX 推理失败: %s", e)
            return (0.5, f"inference_error: {e}")

        max_sim, best_idx = self._compute_similarity(embedding)

        if max_sim >= THRESHOLD_HIGH:
            return (max_sim, f"语义匹配 (score={max_sim:.2f}, idx={best_idx})")
        elif max_sim >= THRESHOLD_LOW:
            return (max_sim, f"边界可疑 (score={max_sim:.2f}, idx={best_idx})")
        else:
            return (max_sim, f"语义安全 (score={max_sim:.2f})")

    def _encode(self, text: str) -> np.ndarray:
        chunks = _chunk_text(text, max_chars=256)
        vectors = []
        for chunk in chunks:
            vec = self._inference_chunk(chunk)
            if vec is not None:
                vectors.append(vec)

        if not vectors:
            return np.zeros(384, dtype=np.float32)
        avg_vec = np.mean(vectors, axis=0)
        norm = np.linalg.norm(avg_vec)
        if norm > 0:
            avg_vec = avg_vec / norm
        return avg_vec.astype(np.float32)

    def _inference_chunk(self, text: str) -> np.ndarray | None:
        tokenizer = self._tokenizer
        if tokenizer is None:
            return None
        try:
            inputs = tokenizer(
                text,
                padding="max_length",
                truncation=True,
                max_length=128,
                return_tensors="np",
            )
            input_feed = {
                "input_ids": inputs["input_ids"].astype(np.int64),
                "attention_mask": inputs["attention_mask"].astype(np.int64),
                "token_type_ids": np.zeros_like(inputs["input_ids"], dtype=np.int64),
            }
            output = self._session.run(None, input_feed)
            # all-MiniLM 输出 shape: (1, seq_len, 384)
            vec = output[0][0].mean(axis=0)
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            return vec.astype(np.float32)
        except Exception as e:
            logger.debug("ONNX chunk inference failed: %s", e)
            return None

    def _compute_similarity(self, embedding: np.ndarray) -> tuple[float, int]:
        """计算与基线样本的最大余弦相似度（纯 numpy，避免引入 sklearn 依赖）

        对 embedding 和基线行都做 L2 归一化，不依赖调用方归一化。
        """
        baseline = self._baseline
        norms = np.linalg.norm(baseline, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        emb_norm = np.linalg.norm(embedding)
        if emb_norm == 0:
            return 0.0, 0
        sims = (baseline / norms) @ (embedding / emb_norm)
        best_idx = int(np.argmax(sims))
        return float(sims[best_idx]), best_idx

    def is_available(self) -> bool:
        return self._available


def _chunk_text(text: str, max_chars: int = 256) -> list[str]:
    """将长文本切分为固定大小的块"""
    if len(text) <= max_chars:
        return [text]
    chunks = []
    for i in range(0, len(text), max_chars):
        chunks.append(text[i:i + max_chars])
    return chunks
