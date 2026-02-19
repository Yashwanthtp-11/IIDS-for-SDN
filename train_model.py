# train_model.py (Version 3.1 - Binary Classification, Joblib Save)
import pandas as pd
import numpy as np
import joblib # <-- CHANGED: Use joblib instead of pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
import time

# --- Use your previously optimized settings (tuned for multi-class) ---
TUNING_SETTINGS = {
    "iteration_name": "Binary Classification (Using Provided CSV)",
    "n_estimators": 200,
    "max_depth": None,
    "min_samples_split": 5,
    "min_samples_leaf": 1
}
# --------------------------------------------

print(f"--- ML Model Training Script Initialized (Binary Classification) ---")
print(f"--- Configuration: {TUNING_SETTINGS['iteration_name']} ---")
start_time = time.time()

# 1. Data Loading
print("1. Loading traffic_data.csv...")
try:
    # Load the CSV you provided (with binary 'label')
    data = pd.read_csv("traffic_data.csv")
    print("   Dataset loaded successfully.")
except FileNotFoundError:
    print("   Error: 'traffic_data.csv' not found. Terminating process.")
    exit()
except KeyError as e:
    print(f"   Error: Missing expected column in CSV: {e}. Cannot proceed.")
    exit()


# 2. Data Preparation
print("\n2. Preparing data for training...")
# Use 'label' as the target
if 'label' not in data.columns:
    print("   Error: Critical column 'label' is missing from the CSV file.")
    exit()

data.dropna(subset=["label"], inplace=True) # Drop rows where the binary label is missing

# Define Features (X) using all columns EXCEPT 'label'
X = data.drop("label", axis=1)
y = data["label"] # Target is the binary label (0 or 1)

categorical_cols = X.select_dtypes(include=["object"]).columns
numeric_cols = X.select_dtypes(include=["int64", "float64"]).columns

# Numeric Conversion and Imputation
X[numeric_cols] = X[numeric_cols].apply(pd.to_numeric, errors="coerce")
X[numeric_cols] = X[numeric_cols].fillna(X[numeric_cols].mean())

# Define the Preprocessor (handles OneHotEncoding)
preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols)
    ],
    remainder="passthrough" # Keep numeric columns
)

# Split RAW data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)
print("   Data successfully prepared and split.")

# 3. Model Training and Evaluation (Binary Classification Pipelines)
print("\n3. Training and evaluating models...")

# --- Decision Tree Pipeline (Benchmark) ---
dt_pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', DecisionTreeClassifier(random_state=42))
])
dt_pipeline.fit(X_train, y_train)
y_pred_dt = dt_pipeline.predict(X_test)
dt_acc = accuracy_score(y_test, y_pred_dt)
print(f"\n   - Decision Tree Accuracy: {dt_acc:.4f}")

# --- Random Forest Pipeline (Optimized Model) ---
rf_pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', RandomForestClassifier(
        n_estimators=TUNING_SETTINGS['n_estimators'],
        max_depth=TUNING_SETTINGS['max_depth'],
        min_samples_split=TUNING_SETTINGS['min_samples_split'],
        min_samples_leaf=TUNING_SETTINGS['min_samples_leaf'],
        random_state=42,
        n_jobs=-1
    ))
])
rf_pipeline.fit(X_train, y_train)
y_pred_rf = rf_pipeline.predict(X_test)

rf_acc = accuracy_score(y_test, y_pred_rf)
# Use binary average for precision/recall
rf_prec = precision_score(y_test, y_pred_rf, average="binary", zero_division=0)
rf_rec = recall_score(y_test, y_pred_rf, average="binary", zero_division=0)

print(f"\n   - Random Forest Accuracy: {rf_acc:.4f}")
print(f"     Random Forest Precision (for label 1): {rf_prec:.4f}")
print(f"     Random Forest Recall (for label 1): {rf_rec:.4f}")

# 4. Model Persistence (Saving the Best Pipeline using joblib)
print("\n4. Persisting best performing pipeline...")
best_pipeline = rf_pipeline if rf_acc >= dt_acc else dt_pipeline

# --- CHANGED: Save using joblib ---
joblib.dump(best_pipeline, "model.pkl")

model_name = "Random Forest" if best_pipeline == rf_pipeline else "Decision Tree"
print(f"   {model_name} pipeline has been saved as model.pkl")

print(f"\n--- ML Model Training Script Finished in {time.time() - start_time:.2f} seconds ---")
