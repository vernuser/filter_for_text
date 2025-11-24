import os
import csv
import argparse
import sys
from pathlib import Path
import logging
from typing import List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.learning_engine import LearningEngine
from ml.deep_models import URLCharMLP, TextTFIDFMLP


def train_url(csv_path: str, url_col: str = 'url', label_col: str = 'label', cap: int = 10000):
    logger = logging.getLogger('train_url')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    if not logger.handlers:
        logger.addHandler(handler)

    engine = LearningEngine()
    urls: List[str] = []
    labels: List[int] = []

    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        logger.error(f'无效CSV: {csv_path}')
        return False

    with open(csv_path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        orig_fields = reader.fieldnames or []
        norm_to_orig = { (c or '').strip().lower(): c for c in orig_fields }
        fields = list(norm_to_orig.keys())
        # 选择实际表头
        if url_col not in fields:
            for c in ['url', 'urls', 'link']:
                if c in fields:
                    url_col = c
                    break
        if label_col not in fields:
            for c in ['label', 'labels', 'type', 'category']:
                if c in fields:
                    label_col = c
                    break
        url_key = norm_to_orig.get(url_col, url_col)
        label_key = norm_to_orig.get(label_col, label_col)
        logger.info(f'列名: url={url_key}, label={label_key}')

        for i, row in enumerate(reader):
            if cap and i >= cap:
                break
            url = row.get(url_key)
            lb_raw = row.get(label_key)
            # 数值标签优先
            label = None
            if lb_raw is not None:
                s = str(lb_raw).strip().lower()
                try:
                    iv = int(s)
                    label = 1 if iv == 1 else 0
                except Exception:
                    label = 0 if s in ('benign', 'good', 'legitimate', 'safe') else 1
            if url and label in (0, 1):
                urls.append(url)
                labels.append(label)

    logger.info(f'样本数: {len(urls)}, 正类比: {sum(labels)}')
    if len(urls) < 10 or len(set(labels)) < 2:
        # 尝试手动解析CSV以兼容异常格式（如空行、BOM等）
        if len(urls) == 0:
            try:
                manual_urls, manual_labels = [], []
                with open(csv_path, 'r', encoding='utf-8') as f:
                    lines = [ln.strip() for ln in f.readlines() if ln.strip()]
                if not lines:
                    logger.error('CSV内容为空')
                    return False
                header = [h.strip().lower() for h in lines[0].split(',')]
                try:
                    u_idx = header.index(url_col) if url_col in header else header.index('url')
                except Exception:
                    u_idx = 0
                try:
                    l_idx = header.index(label_col) if label_col in header else header.index('label')
                except Exception:
                    l_idx = 1 if len(header) > 1 else 0
                for i, ln in enumerate(lines[1:]):
                    parts = [p.strip() for p in ln.split(',')]
                    if cap and i >= cap:
                        break
                    if len(parts) <= max(u_idx, l_idx):
                        continue
                    url = parts[u_idx]
                    s = parts[l_idx].lower()
                    try:
                        iv = int(s)
                        lb = 1 if iv == 1 else 0
                    except Exception:
                        lb = 0 if s in ('benign', 'good', 'legitimate', 'safe') else 1
                    if url:
                        manual_urls.append(url)
                        manual_labels.append(lb)
                if manual_urls:
                    urls, labels = manual_urls, manual_labels
                    logger.info(f'手动解析成功，样本数: {len(urls)}')
            except Exception as e:
                logger.warning(f'手动解析CSV失败: {e}')
        if len(urls) < 10 or len(set(labels)) < 2:
            logger.error('样本不足或类别单一，至少10条且>=2类')
            return False

    deep = URLCharMLP(ngram_range=(3, 5), hidden_layer_sizes=(128,), max_iter=20)
    deep.fit(urls, labels)
    engine.url_deep_model = deep
    engine._save_models()
    logger.info('URL深度模型已训练并保存')
    return True


def train_text(csv_path: str, text_col: str = 'text', label_col: str = 'label', cap: int = 10000):
    logger = logging.getLogger('train_text')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    if not logger.handlers:
        logger.addHandler(handler)

    engine = LearningEngine()
    texts: List[str] = []
    labels: List[int] = []

    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        logger.error(f'无效CSV: {csv_path}')
        return False

    with open(csv_path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        orig_fields = reader.fieldnames or []
        norm_to_orig = { (c or '').strip().lower(): c for c in orig_fields }
        fields = list(norm_to_orig.keys())
        if text_col not in fields:
            for c in ['text', 'content', 'message']:
                if c in fields:
                    text_col = c
                    break
        if label_col not in fields:
            for c in ['label', 'labels', 'type', 'category']:
                if c in fields:
                    label_col = c
                    break
        text_key = norm_to_orig.get(text_col, text_col)
        label_key = norm_to_orig.get(label_col, label_col)
        logger.info(f'列名: text={text_key}, label={label_key}')

        for i, row in enumerate(reader):
            if cap and i >= cap:
                break
            text = row.get(text_key)
            lb_raw = row.get(label_key)
            label = None
            if lb_raw is not None:
                s = str(lb_raw).strip().lower()
                try:
                    iv = int(s)
                    label = 1 if iv == 1 else 0
                except Exception:
                    label = 0 if s in ('benign', 'good', 'legitimate', 'safe') else 1
            if text and label in (0, 1):
                texts.append(text)
                labels.append(label)

    logger.info(f'文本样本数: {len(texts)}')
    if len(texts) < 10 or len(set(labels)) < 2:
        logger.error('样本不足或类别单一，至少10条且>=2类')
        return False

    deep = TextTFIDFMLP(max_features=5000, hidden_layer_sizes=(128,), max_iter=30)
    deep.fit(texts, labels)
    engine.text_deep_model = deep
    engine._save_models()
    logger.info('文本深度模型已训练并保存')
    return True


def train_ip(csv_path: str, ip_col: str = 'ip', label_col: str = 'label', cap: int = 10000):
    logger = logging.getLogger('train_ip')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    if not logger.handlers:
        logger.addHandler(handler)

    engine = LearningEngine()
    ips: List[str] = []
    labels: List[int] = []

    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        logger.error(f'无效CSV: {csv_path}')
        return False

    with open(csv_path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        orig_fields = reader.fieldnames or []
        norm_to_orig = { (c or '').strip().lower(): c for c in orig_fields }
        fields = list(norm_to_orig.keys())
        if ip_col not in fields:
            for c in ['ip', 'address', 'dst_ip', 'src_ip']:
                if c in fields:
                    ip_col = c
                    break
        if label_col not in fields:
            for c in ['label', 'labels', 'type', 'category']:
                if c in fields:
                    label_col = c
                    break
        ip_key = norm_to_orig.get(ip_col, ip_col)
        label_key = norm_to_orig.get(label_col, label_col)
        logger.info(f'列名: ip={ip_key}, label={label_key}')

        for i, row in enumerate(reader):
            if cap and i >= cap:
                break
            ip = row.get(ip_key)
            lb_raw = row.get(label_key)
            label = None
            if lb_raw is not None:
                s = str(lb_raw).strip().lower()
                try:
                    iv = int(s)
                    label = 1 if iv == 1 else 0
                except Exception:
                    label = 0 if s in ('benign', 'good', 'legitimate', 'safe') else 1
            if ip and label in (0, 1):
                ips.append(ip)
                labels.append(label)

    logger.info(f'IP样本数: {len(ips)}')
    if len(ips) < 10 or len(set(labels)) < 2:
        logger.error('样本不足或类别单一，至少10条且>=2类')
        return False

    deep = URLCharMLP(ngram_range=(3, 5), hidden_layer_sizes=(128,), max_iter=20)
    deep.fit(ips, labels)
    engine.ip_deep_model = deep
    engine._save_models()
    logger.info('IP深度模型已训练并保存')
    return True


def main():
    parser = argparse.ArgumentParser(description='训练轻量深度模型（URL/IP/文本）')
    parser.add_argument('--mode', choices=['url', 'ip', 'text'], required=True, help='训练对象')
    parser.add_argument('--csv', required=True, help='CSV数据路径')
    parser.add_argument('--cap', type=int, default=10000, help='样本上限')
    args = parser.parse_args()

    ok = False
    if args.mode == 'url':
        ok = train_url(args.csv, cap=args.cap)
    elif args.mode == 'text':
        ok = train_text(args.csv, cap=args.cap)
    elif args.mode == 'ip':
        ok = train_ip(args.csv, cap=args.cap)

    if not ok:
        sys.exit(1)


if __name__ == '__main__':
    main()
