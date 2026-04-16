import pandas as pd
import os

df = pd.read_csv('Datasets.csv')

print("--- Shape ---")
print(df.shape)

print("\n--- Columns ---")
print(df.columns.tolist())

print("\n--- Data Types ---")
print(df.dtypes)

print("\n--- Missing Values ---")
print(df.isnull().sum())

print("\n--- Duplicate Rows ---")
print(df.duplicated().sum())

print("\n--- Target Class Distribution (Attack_Type) ---")
print(df['Attack_Type'].value_counts())

print("\n--- Unique Values in Categorical Columns ---")
cat_cols = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken']
for col in cat_cols:
    if col in df.columns:
        print(f"{col}: {df[col].nunique()} unique values")

print("\n--- Numerical Column Stats ---")
num_cols = ['Packet_Length', 'Anomaly_Scores', 'Source_Port', 'Destination_Port']
for col in num_cols:
    if col in df.columns:
        # Convert to numeric if possible
        df[col] = pd.to_numeric(df[col], errors='coerce')
        print(f"{col} - Mean: {df[col].mean():.2f}, Min: {df[col].min()}, Max: {df[col].max()}")
