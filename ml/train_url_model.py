import os
import csv
import argparse
from typing import Optional, List
import sys
from pathlib import Path
import logging

# 确保项目根目录在导入路径中，便于找到config与ml包
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.learning_engine import LearningEngine
from ml.deep_models import URLCharMLP


LABEL_MAP = {
    # 常见标签映射
    'malicious': 1, 'bad': 1, 'phishing': 1, 'spam': 1, 'defacement': 1,
    'benign': 0, 'good': 0, 'safe': 0, 'legitimate': 0
}


def normalize_label(value) -> Optional[int]:
    if value is None:
        return None
    try:
        # 数字标签
        iv = int(value)
        return 1 if iv == 1 else 0
    except Exception:
        # 文本标签
        s = str(value).strip().lower()
        return LABEL_MAP.get(s)


def import_dataset(csv_path: str, url_column: str = 'url', label_column: str = 'label', train_deep: bool = True, sample_cap: int = 5000):
    logger = logging.getLogger('train_url_model')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    if not logger.handlers:
        logger.addHandler(handler)

    engine = LearningEngine()
    added = 0
    urls: List[str] = []
    labels: List[int] = []

    # 导入保护：文件存在、大小校验
    if not os.path.exists(csv_path):
        logger.error(f"CSV文件不存在: {csv_path}")
        return
    if os.path.getsize(csv_path) == 0:
        logger.error(f"CSV文件为空: {csv_path}")
        return

    logger.info(f"开始导入数据: {csv_path}")
    try:
        with open(csv_path, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            # 自动侦测列名
            fieldnames = [c.strip().lower() for c in (reader.fieldnames or [])]
            if url_column not in fieldnames:
                # 常见候选
                for c in ['url', 'urls', 'link']:
                    if c in fieldnames:
                        url_column = c
                        break
            if label_column not in fieldnames:
                for c in ['label', 'labels', 'type', 'category']:
                    if c in fieldnames:
                        label_column = c
                        break
            logger.info(f"使用列: url_col={url_column}, label_col={label_column}")

            for i, row in enumerate(reader):
                if sample_cap and i >= sample_cap:
                    break
                url = row.get(url_column)
                label_raw = row.get(label_column)
                # Kaggle malicious_phish 的label为type，非benign视为恶意
                label = normalize_label(label_raw)
                if label is None and label_raw is not None:
                    s = str(label_raw).strip().lower()
                    label = 0 if s in ('benign', 'good', 'legitimate', 'safe') else 1

                if not url or label is None:
                    continue

                # 先将样本纳入用于深度模型训练的集合
                urls.append(url)
                labels.append(label)
                # 再尝试落库（去重由数据库/引擎负责）
                ok = engine.add_training_sample(url, 'url', label, confidence=1.0, source='external')
                if ok:
                    added += 1

        logger.info(f"导入训练样本完成，共新增 {added} 条")
    except Exception as e:
        logger.exception(f"导入数据失败: {e}")
        return

    # 训练深度模型（轻量MLP）
    # 深度模型训练条件：样本数与类别至少两个
    if train_deep and len(urls) >= 10 and len(set(labels)) >= 2:
        try:
            logger.info(f"开始训练轻量深度模型（URLCharMLP），样本数={len(urls)}")
            deep_model = URLCharMLP(ngram_range=(3, 5), hidden_layer_sizes=(128,), max_iter=20)
            deep_model.fit(urls, labels)
            engine.url_deep_model = deep_model
            engine._save_models()
            logger.info("深度模型训练并保存完成")
        except Exception as e:
            logger.exception(f"深度模型训练失败: {e}")
    else:
        logger.warning("样本不足或类别不足，跳过深度模型训练（至少10条且>=2类）")

    # 触发传统模型训练（如需要）
    logger.info("开始训练传统URL分类器...")
    result = engine.train_models(force_retrain=True)
    logger.info(f"训练结果: {result}")


def main():
    parser = argparse.ArgumentParser(description='使用外部数据训练URL恶意检测模型')
    parser.add_argument('--csv', required=True, help='数据集CSV路径（包含url与label列）')
    parser.add_argument('--url-col', default='url', help='URL列名，默认url')
    parser.add_argument('--label-col', default='label', help='标签列名，默认label')
    parser.add_argument('--no-deep', action='store_true', help='不训练轻量深度模型')
    parser.add_argument('--cap', type=int, default=5000, help='导入样本上限，默认5000')
    args = parser.parse_args()

    import_dataset(args.csv, url_column=args.url_col, label_column=args.label_col, train_deep=(not args.no_deep), sample_cap=args.cap)


if __name__ == '__main__':
    main()
