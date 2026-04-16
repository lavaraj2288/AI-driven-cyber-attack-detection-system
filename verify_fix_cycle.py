import os
import django
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from imblearn.pipeline import Pipeline as ImbPipeline

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'role_of_ai.settings')
django.setup()

from django.conf import settings

def simulate_training():
    print("Simulating Admin Training...")
    df = pd.read_csv(os.path.join(settings.BASE_DIR, "Datasets.csv"))
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2, "Normal": 3}
    df["results"] = df["Attack_Type"].map(mapping)
    df = df.dropna(subset=['results'])

    num_features = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores']
    cat_features = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment']
    
    for col in num_features:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    df = df.dropna(subset=num_features + cat_features)
    X = df[num_features + cat_features]
    y = df["results"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

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

    best_pipeline = ImbPipeline(steps=[
        ('preprocessor', preprocessor),
        ('model', RandomForestClassifier(n_estimators=10, random_state=42))
    ])
    best_pipeline.fit(X_train, y_train)
    
    model_path = os.path.join(settings.BASE_DIR, 'trained_model.joblib')
    joblib.dump(best_pipeline, model_path)
    print(f"Model saved to {model_path}")

def simulate_prediction():
    print("\nSimulating User Prediction...")
    model_path = os.path.join(settings.BASE_DIR, 'trained_model.joblib')
    if not os.path.exists(model_path):
        print("Model file not found!")
        return

    clf = joblib.load(model_path)
    print("Model loaded successfully.")

    # Test with a DDoS sample
    test_input = pd.DataFrame([{
        'Source_Port': 80,
        'Destination_Port': 8080,
        'Packet_Length': 1500,
        'Anomaly_Scores': 0.9,
        'Protocol': 'TCP',
        'Packet_Type': 'Data',
        'Traffic_Type': 'HTTP',
        'Severity_Level': 'High',
        'Action_Taken': 'Logged',
        'Network_Segment': 'Internal',
        'Payload_Data': 'GET /admin HTTP/1.1'
    }])

    result = clf.predict(test_input)[0]
    attack_type = {0: 'Malware', 1: 'DDoS', 2: 'Intrusion', 3: 'Normal'}.get(result)
    
    if attack_type == 'Normal':
        val = "No Cyber Attack Detected (Normal Traffic)"
    else:
        val = f"Cyber Attack Detected: {attack_type} Attack"
    
    print(f"Prediction Result: {val}")
    
    if "DDoS" in val or "Malware" in val or "Intrusion" in val:
        print("SUCCESS: Detection working.")
    else:
        print("FAILURE: Did not detect attack.")

if __name__ == "__main__":
    simulate_training()
    simulate_prediction()
