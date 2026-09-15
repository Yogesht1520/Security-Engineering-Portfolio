# DEMO SECRET - NOT REAL - NONFUNCTIONAL
# This file contains intentionally fake secrets so TruffleHog has something to find in Phase 1
# No real secrets exist in this repository

class Config:
    # FAKE AWS KEY - TRUFFLEHOG TARGET
   # AWS_ACCESS_KEY_ID = "AKIADEMOEXAMPLE00000"
   # AWS_SECRET_ACCESS_KEY = "DEMO/FAKE/KEY/DO_NOT_USE_0000000000000"

    # FAKE DB PASSWORD
    DB_PASSWORD = "Password123!@#super_secret_demo_password"
    DB_CONNECTION_STRING = f"postgresql://admin:{DB_PASSWORD}@database.internal:5432/main_db"
