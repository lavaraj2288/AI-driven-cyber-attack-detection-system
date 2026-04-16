import pandas as pd
import numpy as np
import os

# Load original dataset
df = pd.read_csv('Datasets.csv')

# Unique columns to maintain structure
cols = df.columns.tolist()

# Sample normal activity strings for Fid
normal_fid_samples = [
    "User Login Success",
    "Home Page Access",
    "Dashboard Navigation",
    "Profile Update",
    "Settings Changed",
    "Search Query: help",
    "Search Query: products",
    "Image Load: logo.png",
    "CSS Fetch: styles.css",
    "JS Load: main.js",
    "Logout Success",
    "View Cart",
    "Checkout Started",
    "Contact Form Submission",
    "FAQ Page View"
]

# Generate 1000 normal rows
n_rows = 1000
new_data = []

for i in range(n_rows):
    # Take a random row from the original to get common values for other columns
    sample_row = df.sample(n=1).iloc[0].to_dict()
    
    # Override with Normal values
    sample_row['Attack_Type'] = 'Normal'
    sample_row['Fid'] = np.random.choice(normal_fid_samples)
    sample_row['Severity_Level'] = 'Low'
    sample_row['Action_Taken'] = 'Logged'
    sample_row['Alerts_Warnings'] = 'None'
    sample_row['Malware_Indicators'] = 'None'
    sample_row['Anomaly_Scores'] = 0.05 + (0.1 * np.random.random()) # Low anomaly score
    
    new_data.append(sample_row)

# Create DataFrame and append
normal_df = pd.DataFrame(new_data)
final_df = pd.concat([df, normal_df], ignore_index=True)

# Save back to CSV
final_df.to_csv('Datasets.csv', index=False)
print(f"Successfully added {n_rows} 'Normal' rows to Datasets.csv")
