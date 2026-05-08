import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest
from features import extract_features

MODEL_PATH = "model_saved.pkl"

def train_and_save(csv_path: str = "dummy/audit_logs.csv"):
    print("데이터 로드")
    df = pd.read_csv(csv_path)
    features_df = extract_features(df)
    
    feature_cols = [
        "requests_per_min",
        "avg_hour",
        "login_fail_count",
        "unique_endpoints",
        "top_ip_ratio",
        "forbidden_ratio",
        "avg_serror_rate",
        "avg_rerror_rate",
        "avg_diff_srv_rate",
        "avg_count",
    ]
    X = features_df[feature_cols]
    
    # 정상 데이터로만 학습
    normal_X = X[features_df["user_id"] < 900]
    
    model = IsolationForest(
        contamination=0.03,
        random_state=42
    )
    model.fit(normal_X)
    
    # 모델 저장
    joblib.dump(model, MODEL_PATH)
    print(f"모델 저장 완료: {MODEL_PATH}")
    
    return model, features_df, X

def load_model():
    if os.path.exists(MODEL_PATH):
        print("저장된 모델 로드 중")
        return joblib.load(MODEL_PATH)
    else:
        print("저장된 모델 없음 → 새로 학습")
        model, _, _ = train_and_save()
        return model

def train_and_predict(csv_path: str = "dummy/audit_logs.csv"):
    df = pd.read_csv(csv_path)
    features_df = extract_features(df)
    
    feature_cols = [
        "requests_per_min",
        "avg_hour",
        "login_fail_count",
        "unique_endpoints",
        "top_ip_ratio",
        "forbidden_ratio",
        "avg_serror_rate",
        "avg_rerror_rate",
        "avg_diff_srv_rate",
        "avg_count",
    ]
    X = features_df[feature_cols]
    
    # 저장된 모델 로드 or 새로 학습
    model = load_model()
    
    features_df["score"] = model.predict(X)
    
    def classify_risk(row):
        if row["score"] == -1:
            if row["login_fail_count"] >= 5 or row["forbidden_ratio"] >= 0.3:
                return "HIGH"
            elif row["requests_per_min"] >= 1.0 or row["avg_hour"] <= 5:
                return "HIGH"
            else:
                return "MEDIUM"
        return "NORMAL"
    
    features_df["risk_level"] = features_df.apply(classify_risk, axis=1)
    
    # 성능 검증
    print("\n모델 성능 검증")
    print(f"전체 유저 수: {len(features_df)}명")
    
    normal_users = features_df[features_df["user_id"] < 900]
    attack_users = features_df[features_df["user_id"] >= 900]
    
    false_positive = normal_users[normal_users["risk_level"] != "NORMAL"]
    false_negative = attack_users[attack_users["risk_level"] == "NORMAL"]
    detected = attack_users[attack_users["risk_level"] != "NORMAL"]
    
    print(f"오탐 (정상 → 이상 탐지): {len(false_positive)}명")
    print(f"미탐 (공격 → 정상 탐지): {len(false_negative)}명")
    print(f"공격 탐지율: {len(detected) / len(attack_users) * 100:.1f}%")
    
    result = features_df[features_df["risk_level"] != "NORMAL"]
    print(f"\n탐지 완료: 이상 유저 {len(result)}명")
    
    return features_df

if __name__ == "__main__":
    # 처음 실행 시 학습 + 저장
    train_and_save()
    # 예측
    train_and_predict()