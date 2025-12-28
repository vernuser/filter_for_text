#炼模型
import logging
from typing import List, Union

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.neural_network import MLPClassifier


class URLCharMLP:


    def __init__(self, ngram_range=(3, 5), hidden_layer_sizes=(128,), max_iter=20):
        self.logger = logging.getLogger(__name__)
        self.vectorizer = CountVectorizer(analyzer='char', ngram_range=ngram_range, min_df=1)
        self.model = MLPClassifier(hidden_layer_sizes=hidden_layer_sizes, activation='relu', solver='adam',
                                   max_iter=max_iter, random_state=42)
        self.fitted = False

    def fit(self, urls: List[str], labels: List[int]):
        X = self.vectorizer.fit_transform(urls)
        y = np.array(labels)
        self.model.fit(X, y)
        self.fitted = True
        return self

    def predict_proba(self, urls: Union[str, List[str]]):
        single = False
        if isinstance(urls, str):
            urls = [urls]
            single = True
        # 未训练保护：返回中性概率，避免抛出异常
        if not self.fitted:
            self.logger.warning("URLCharMLP 未训练，返回中性概率")
            neutral = np.array([[0.5, 0.5]] * len(urls))
            return neutral[0] if single else neutral
        X = self.vectorizer.transform(urls)
        probs = self.model.predict_proba(X)
        return probs[0] if single else probs


class TextTFIDFMLP:

    def __init__(self, max_features=5000, hidden_layer_sizes=(128,), max_iter=30):
        self.vectorizer = TfidfVectorizer(max_features=max_features, ngram_range=(1, 2))
        self.model = MLPClassifier(hidden_layer_sizes=hidden_layer_sizes, activation='relu', solver='adam',
                                   max_iter=max_iter, random_state=42)
        self.fitted = False

    def fit(self, texts: List[str], labels: List[int]):
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)
        self.model.fit(X, y)
        self.fitted = True
        return self

    def predict_proba(self, texts: Union[str, List[str]]):
        single = False
        if isinstance(texts, str):
            texts = [texts]
            single = True
        # 未训练保护：返回中性概率，避免抛出异常
        if not self.fitted:
            logging.getLogger(__name__).warning("TextTFIDFMLP 未训练，返回中性概率")
            neutral = np.array([[0.5, 0.5]] * len(texts))
            return neutral[0] if single else neutral
        X = self.vectorizer.transform(texts)
        probs = self.model.predict_proba(X)
        return probs[0] if single else probs
