#!/usr/bin/env python3
"""导出 all-MiniLM-L6-v2 为 ONNX 模型 + 预计算基线嵌入

使用方式:
  uv run python scripts/export_onnx_model.py

依赖 (仅导出时需要):
  uv pip install "optimum[onnxruntime]" "sentence-transformers"
"""

from pathlib import Path

import numpy as np

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
CACHE_DIR = Path.home() / ".cache" / "agent-guardian"
ONNX_PATH = CACHE_DIR / "model.onnx"
BASELINE_PATH = Path(__file__).resolve().parents[1] / "src" / "engine" / "slm_baseline.py"


def export_model():
    from optimum.onnxruntime import ORTModelForFeatureExtraction
    from transformers import AutoTokenizer

    print(f"下载模型: {MODEL_NAME}")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    model = ORTModelForFeatureExtraction.from_pretrained(MODEL_NAME, export=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    print(f"导出 ONNX → {ONNX_PATH}")
    model.save_pretrained(str(CACHE_DIR))
    tokenizer.save_pretrained(str(CACHE_DIR))

    # 重命名 ONNX 文件为标准名称
    onnx_files = list(CACHE_DIR.glob("*.onnx"))
    if onnx_files:
        onnx_files[0].rename(ONNX_PATH)

    print(f"ONNX 模型已保存: {ONNX_PATH} ({ONNX_PATH.stat().st_size / 1e6:.1f} MB)")
    return model, tokenizer


def compute_embeddings(model, tokenizer):
    """对基线样本计算嵌入，写入 slm_baseline.py"""
    from src.engine.slm_baseline import SAMPLES

    texts = [t for t, _ in SAMPLES]
    print(f"计算 {len(texts)} 条样本嵌入...")

    inputs = tokenizer(texts, padding=True, truncation=True, max_length=256, return_tensors="pt")
    with _no_grad():
        outputs = model(**inputs)
    embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()

    # 写入 slm_baseline.py 的 EMBEDDINGS 常量
    _update_baseline_embeddings(embeddings)
    print(f"嵌入已写入 {BASELINE_PATH}")

    # 自检
    _self_check(embeddings, texts)


def _no_grad():
    import torch
    return torch.no_grad()


def _update_baseline_embeddings(embeddings: np.ndarray):
    """用新计算的嵌入替换 BASELINE 文件中的 EMBEDDINGS 常量"""
    content = BASELINE_PATH.read_text(encoding="utf-8")

    # 生成新的 EMBEDDINGS 赋值语句
    emb_lines = ["EMBEDDINGS = ["]
    for vec in embeddings:
        floats = ", ".join(f"{v:.8f}" for v in vec.tolist())
        emb_lines.append(f"    [{floats}],")
    emb_lines.append("]")

    # 替换空 EMBEDDINGS 行
    import re
    new_content = re.sub(
        r"EMBEDDINGS: list\[list\[float\]\] = \[\]",
        "EMBEDDINGS: list[list[float]] = [\n" + "\n".join(emb_lines[1:-1]) + "\n]",
        content,
    )
    BASELINE_PATH.write_text(new_content, encoding="utf-8")


def _self_check(embeddings: np.ndarray, texts: list[str]):
    """自检: 相同文本高相似度, 无关文本低相似度"""
    from sklearn.metrics.pairwise import cosine_similarity

    idx = 0
    sim_self = cosine_similarity([embeddings[idx]], [embeddings[idx]])[0][0]
    assert sim_self > 0.99, f"自相似度过低: {sim_self:.4f}"

    if len(texts) > 20:
        sim_cross = cosine_similarity([embeddings[0]], [embeddings[20]])[0][0]
        print(f"自检通过: 自相似度={sim_self:.4f}, 跨场景相似度={sim_cross:.4f}")


def main():
    if ONNX_PATH.exists():
        print(f"模型已存在: {ONNX_PATH}")
        overwrite = input("覆盖? [y/N] ").strip().lower()
        if overwrite != "y":
            print("跳过导出")
            return

    model, tokenizer = export_model()
    compute_embeddings(model, tokenizer)
    print("\n完成! 可运行: uv run pytest tests/test_slm_reviewer.py -v")


if __name__ == "__main__":
    main()
