import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

def test_enhanced_features():
    df = pd.read_csv("Datasets.csv")
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2}
    df["results"] = df["Attack_Type"].map(mapping)
    
    # Feature Engineering
    df['Src_Dest_Port_Diff'] = df['Destination_Port'] - df['Source_Port']
    df['Packet_Anomaly_Ratio'] = df['Packet_Length'] / (df['Anomaly_Scores'] + 1)
    
    # Time-based features
    try:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df['Hour'] = df['Timestamp'].dt.hour
        df['Minute'] = df['Timestamp'].dt.minute
        df['DayOfWeek'] = df['Timestamp'].dt.dayofweek
    except:
        df['Hour'] = 0
        df['Minute'] = 0
        df['DayOfWeek'] = 0

    num_features = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores', 'Src_Dest_Port_Diff', 'Packet_Anomaly_Ratio', 'Hour', 'Minute', 'DayOfWeek']
    cat_features = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment']
    
    for col in num_features:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df = df.dropna(subset=['results'] + num_features)
    
    X = df[num_features + cat_features]
    y = df["results"]

    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])

    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
        ('onehot', OneHotEncoder(handle_unknown='ignore'))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, num_features),
            ('cat', categorical_transformer, cat_features)
        ])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training Enhanced Random Forest...")
    pipeline = ImbPipeline(steps=[
        ('preprocessor', preprocessor),
        ('smote', SMOTE(random_state=42)),
        ('model', RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42))
    ])
    
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    
    print(f"Enhanced Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    test_enhanced_features()
