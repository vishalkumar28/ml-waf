import pickle, numpy as np, pandas as pd
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from backend.features.extractor import extract_features

def build_X(payloads, tfidf=None, fit=False):
    # Character n-gram TF-IDF (bypass resistant)
    if fit:
        tfidf = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 5),
            max_features=30000,
            sublinear_tf=True
        )
        tfidf_X = tfidf.fit_transform(payloads)
    else:
        tfidf_X = tfidf.transform(payloads)

    # Numerical features
    num_X = np.array([list(extract_features(p).values()) for p in payloads])
    combined = sp.hstack([tfidf_X, sp.csr_matrix(num_X)])
    return combined, tfidf

def train():
    df = pd.read_csv('../../ml_pipeline/datasets/train.csv')
    payloads = df['payload'].tolist()
    labels   = df['label'].tolist()

    X, tfidf = build_X(payloads, fit=True)
    y = np.array(labels)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X, y)

    # Save model + vectorizer
    with open('models/model_v1.pkl', 'wb') as f: pickle.dump(model, f)
    with open('models/tfidf_v1.pkl', 'wb') as f: pickle.dump(tfidf, f)

    # Quick evaluation
    test_df = pd.read_csv('../../ml_pipeline/datasets/test.csv')
    X_test, _ = build_X(test_df['payload'].tolist(), tfidf=tfidf)
    y_test = test_df['label'].values
    preds = model.predict(X_test)
    print(classification_report(y_test, preds, target_names=['Benign','Malicious']))
    print(f"AUC: {roc_auc_score(y_test, model.predict_proba(X_test)[:,1]):.4f}")

if __name__ == '__main__':
    train()