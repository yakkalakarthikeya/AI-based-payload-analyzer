import pandas as pd
import pickle
import re

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# -------------------------
# LOAD DATA
# -------------------------
df = pd.read_csv("Modified_SQL_Dataset.csv")
df.columns = df.columns.str.strip().str.lower()

print("Columns:", list(df.columns))

# Your dataset columns
X = df["query"].astype(str).str.strip()
y = df["label"].astype(int)

# -------------------------
# CLEAN DATA
# -------------------------
df = pd.DataFrame({"query": X, "label": y})
df = df.dropna()
df = df[df["query"].str.len() > 0]
df = df.drop_duplicates(subset=["query", "label"]).reset_index(drop=True)

X = df["query"]
y = df["label"]

print("\nLabel distribution:")
print(y.value_counts())

# -------------------------
# SPLIT DATA
# -------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# -------------------------
# TF-IDF VECTORIZER
# -------------------------
vectorizer = TfidfVectorizer(
    analyzer="char_wb",
    ngram_range=(2, 6),
    max_features=12000,
    lowercase=True,
    sublinear_tf=True
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

# -------------------------
# RANDOM FOREST MODEL
# -------------------------
model = RandomForestClassifier(
    n_estimators=400,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_vec, y_train)

# -------------------------
# EVALUATION
# -------------------------
y_pred = model.predict(X_test_vec)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# -------------------------
# SAVE MODEL + VECTORIZER
# -------------------------
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("\nModel and vectorizer saved successfully.")