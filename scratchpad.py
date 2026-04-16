import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from imblearn.over_sampling import SMOTE

def experimental_work():
    print("--- Starting Scratchpad Experiment ---")
    
    if not os.path.exists("Datasets.csv"):
        print("Datasets.csv not found.")
        return

    df = pd.read_csv("Datasets.csv")
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2}
    df["results"] = df["Attack_Type"].map(mapping)
    df = df.dropna(subset=['results'])

    # 1. Advanced Feature Engineering
    # Interaction between ports and payload length
    df['Port_Interaction'] = df['Source_Port'] * df['Destination_Port']
    df['Len_Anomaly_Interaction'] = df['Packet_Length'] * df['Anomaly_Scores']
    
    # Text features - deeper TF-IDF
    tfidf = TfidfVectorizer(max_features=500, ngram_range=(1,2))
    text_features = tfidf.fit_transform(df['Payload_Data'].fillna('none'))
    
    # Categorical encoding
    le = LabelEncoder()
    cat_cols = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment']
    for col in cat_cols:
        df[col] = le.fit_transform(df[col].astype(str))

    num_cols = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores', 'Port_Interaction', 'Len_Anomaly_Interaction']
    
    X_num = df[num_cols + cat_cols].values
    X_text = text_features.toarray()
    
    X = np.hstack([X_num, X_text])
    y = df['results'].values

    # 2. Model Testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

    # Try LightGBM which is very strong
    print("Training LightGBM...")
    lgbm = LGBMClassifier(n_estimators=200, learning_rate=0.05, num_leaves=31, random_state=42)
    lgbm.fit(X_train_res, y_train_res)
    
    score = lgbm.score(X_test, y_test)
    print(f"LightGBM Test Accuracy: {score:.4f}")

    # Try XGBoost with more depth
    print("Training XGBoost...")
    xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.05, random_state=42)
    xgb.fit(X_train_res, y_train_res)
    
    score_xgb = xgb.score(X_test, y_test)
    print(f"XGBoost Test Accuracy: {score_xgb:.4f}")

    if score > 0.40 or score_xgb > 0.40:
        print("!!! Signal Found !!!")
    else:
        print("Still around random baseline. The dataset columns likely contain no relationship to the labels.")

if __name__ == "__main__":
    experimental_work()
