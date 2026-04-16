import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

def test_ml_pipeline():
    print("Testing ML Pipeline...")
    
    # Load dataset
    if not os.path.exists("Datasets.csv"):
        print("Datasets.csv not found!")
        return
        
    df = pd.read_csv("Datasets.csv")
    print(f"Original shape: {df.shape}")

    # 1. Data Cleaning
    df = df.drop_duplicates()
    
    # 2. Map target
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2}
    df["results"] = df["Attack_Type"].map(mapping)
    
    # 3. Feature Selection
    num_features = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores']
    cat_features = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken']
    
    for col in num_features:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df = df.dropna(subset=['results'] + num_features + cat_features)
    print(f"Cleaned shape: {df.shape}")

    X = df[num_features + cat_features]
    y = df["results"]

    # 4. Preprocessing Pipeline
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

    # 5. Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 6. Test with Random Forest (simplified for speed)
    print("Training Random Forest...")
    pipeline = ImbPipeline(steps=[
        ('preprocessor', preprocessor),
        ('smote', SMOTE(random_state=42)),
        ('model', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

if __name__ == "__main__":
    test_ml_pipeline()
