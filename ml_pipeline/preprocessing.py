import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.utils import resample

# ── Load all .txt payload files from a folder ──
def load_payloads_from_folder(folder_path, label):
    payloads = []
    for fname in os.listdir(folder_path):
        if fname.endswith('.txt') or fname.endswith('.csv'):
            fpath = os.path.join(folder_path, fname)
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        payloads.append({'payload': line, 'label': label})
    return pd.DataFrame(payloads)

# ── Generate simple benign samples ──
def generate_benign_samples(n=5000):
    samples = [
        "GET /index.html HTTP/1.1",
        "username=john&password=hello123",
        "search=laptop&category=electronics",
        "page=1&limit=20&sort=date",
        "email=user@example.com&name=John+Doe",
        "id=42&action=view",
        "q=python+tutorial&lang=en",
    ]
    rows = []
    import random
    for _ in range(n):
        rows.append({'payload': random.choice(samples), 'label': 0})
    return pd.DataFrame(rows)

def build_dataset():
    mal = load_payloads_from_folder('datasets/malicious', label=1)
    ben = generate_benign_samples(n=len(mal))  # balance sizes

    df = pd.concat([mal, ben]).sample(frac=1, random_state=42).reset_index(drop=True)
    df = df.drop_duplicates(subset=['payload'])
    df = df.dropna()

    train_df, test_df = train_test_split(df, test_size=0.2,
                                         stratify=df['label'],
                                         random_state=42)
    train_df.to_csv('datasets/train.csv', index=False)
    test_df.to_csv('datasets/test.csv', index=False)
    print(f"Train: {len(train_df)} samples | Test: {len(test_df)} samples")
    print(df['label'].value_counts())

if __name__ == '__main__':
    build_dataset()