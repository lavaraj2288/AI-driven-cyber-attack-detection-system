import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier

def verify_prediction_logic():
    print("Verifying Prediction Logic...")
    
    # 1. Load data
    if not os.path.exists('Datasets.csv'):
        print("Datasets.csv not found!")
        return
        
    df = pd.read_csv('Datasets.csv')
    print(f"Loaded {len(df)} rows.")

    # 2. Map target
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2, "Normal": 3}
    df["results"] = df["Attack_Type"].map(mapping)
    df = df.dropna(subset=['results'])

    # 3. Features
    num_features = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores']
    cat_features = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment']
    
    # 4. Clean numeric data
    for col in num_features:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df = df.dropna(subset=num_features + cat_features)
    print(f"Cleaned data: {len(df)} rows.")

    X = df[num_features + cat_features]
    y = df["results"]

    # 5. Preprocessing Pipeline
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

    # 6. Fit Model
    print("Training Random Forest...")
    clf = Pipeline(steps=[('preprocessor', preprocessor),
                          ('classifier', RandomForestClassifier(n_estimators=10, random_state=42))]) # Small for speed
    
    clf.fit(X, y)
    print("Training complete.")

    # 7. Test with a sample 'Normal' row from dataset if possible
    normal_samples = df[df['Attack_Type'] == 'Normal'].head(1)
    if not normal_samples.empty:
        sample = normal_samples.iloc[0]
        test_input = pd.DataFrame([{
            'Source_Port': sample['Source_Port'],
            'Destination_Port': sample['Destination_Port'],
            'Packet_Length': sample['Packet_Length'],
            'Anomaly_Scores': sample['Anomaly_Scores'],
            'Protocol': sample['Protocol'],
            'Packet_Type': sample['Packet_Type'],
            'Traffic_Type': sample['Traffic_Type'],
            'Severity_Level': sample['Severity_Level'],
            'Action_Taken': sample['Action_Taken'],
            'Network_Segment': sample['Network_Segment']
        }])
        
        pred = clf.predict(test_input)[0]
        pred_label = {0: 'Malware', 1: 'DDoS', 2: 'Intrusion', 3: 'Normal'}.get(pred)
        print(f"Test Prediction (Input: Normal): {pred_label}")
        if pred_label == 'Normal':
            print("SUCCESS: Correctly predicted Normal traffic.")
        else:
            print("FAILURE: Incorrect prediction for Normal traffic.")

    # 8. Test with a sample 'DDoS' row
    ddos_samples = df[df['Attack_Type'] == 'DDoS'].head(1)
    if not ddos_samples.empty:
        sample = ddos_samples.iloc[0]
        test_input = pd.DataFrame([{
            'Source_Port': sample['Source_Port'],
            'Destination_Port': sample['Destination_Port'],
            'Packet_Length': sample['Packet_Length'],
            'Anomaly_Scores': sample['Anomaly_Scores'],
            'Protocol': sample['Protocol'],
            'Packet_Type': sample['Packet_Type'],
            'Traffic_Type': sample['Traffic_Type'],
            'Severity_Level': sample['Severity_Level'],
            'Action_Taken': sample['Action_Taken'],
            'Network_Segment': sample['Network_Segment']
        }])
        
        pred = clf.predict(test_input)[0]
        pred_label = {0: 'Malware', 1: 'DDoS', 2: 'Intrusion', 3: 'Normal'}.get(pred)
        print(f"Test Prediction (Input: DDoS): {pred_label}")
        if pred_label == 'DDoS':
            print("SUCCESS: Correctly predicted DDoS attack.")
        else:
            print("FAILURE: Incorrect prediction for DDoS attack.")

if __name__ == "__main__":
    verify_prediction_logic()
