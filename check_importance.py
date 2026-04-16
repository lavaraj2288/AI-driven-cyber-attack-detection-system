import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier

def check_importance():
    df = pd.read_csv("Datasets.csv")
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2}
    df["results"] = df["Attack_Type"].map(mapping)
    
    # Encode all categorical
    le = LabelEncoder()
    cat_cols = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment', 'Device_Information', 'Log_Source']
    for col in cat_cols:
        df[col] = le.fit_transform(df[col].astype(str))
        
    num_cols = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores']
    for col in num_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df = df.dropna(subset=['results'] + num_cols)
    
    X = df[cat_cols + num_cols]
    y = df["results"]
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X, y)
    
    importances = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
    print("Feature Importances:")
    print(importances)

if __name__ == "__main__":
    check_importance()
