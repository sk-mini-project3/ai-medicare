import pandas as pd
import joblib
import os
import shutil
import time
from sklearn.ensemble import IsolationForest
from features import extract_features
from database import fetch_audit_logs

MODEL_PATH = "model_saved.pkl"
MODEL_BACKUP_PATH = "model_saved_backup.pkl"


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

    normal_X = X[features_df["user_id"] < 900]

    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(normal_X)

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


def retrain_model():
    """
    RDS AuditLog 데이터로 모델 재학습 후 저장.
    기존 모델은 백업 후 교체.
    """
    start = time.time()

    # RDS 데이터 로드
    print("RDS 데이터 로드 중...")
    df = fetch_audit_logs()

    if df.empty:
        raise ValueError("RDS에 학습할 데이터가 없습니다.")

    row_count = len(df)
    print(f"로드된 로그: {row_count}건")

    # 피처 추출
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

    # 기존 모델 백업
    if os.path.exists(MODEL_PATH):
        shutil.copy(MODEL_PATH, MODEL_BACKUP_PATH)
        print(f"기존 모델 백업 완료: {MODEL_BACKUP_PATH}")

    # 재학습 (RDS는 정상/공격 구분 없으므로 전체 데이터로 학습)
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(X)

    joblib.dump(model, MODEL_PATH)

    elapsed = round(time.time() - start, 2)
    print(f"재학습 완료 ({elapsed}초)")

    return {
        "row_count": row_count,
        "user_count": len(features_df),
        "elapsed_sec": elapsed,
    }


def classify_risk(row):
    if row["score"] == -1:
        reasons = []

        if row["login_fail_count"] >= 5:
            reasons.append(f"로그인 실패 {int(row['login_fail_count'])}회")
        if row["forbidden_ratio"] >= 0.3:
            reasons.append(f"403 에러 비율 {round(row['forbidden_ratio']*100)}%")
        if row["requests_per_min"] >= 5.0:
            reasons.append(f"분당 요청 {round(row['requests_per_min'], 1)}회")
        if row["avg_hour"] <= 5:
            reasons.append(f"새벽 시간대 접근 (평균 {round(row['avg_hour'], 1)}시)")
        if row["avg_serror_rate"] >= 0.5:
            reasons.append("SYN 에러 비율 높음")
        if row["avg_rerror_rate"] >= 0.5:
            reasons.append("REJ 에러 비율 높음")

        reason = ", ".join(reasons) if reasons else "비정상 접근 패턴 감지"

        if row["login_fail_count"] >= 5 or row["forbidden_ratio"] >= 0.3:
            return "HIGH", reason
        elif row["requests_per_min"] >= 5.0 or row["avg_hour"] <= 5:
            return "HIGH", reason
        else:
            return "MEDIUM", reason

    return "NORMAL", ""


def train_and_predict(use_rds: bool = False, csv_path: str = "dummy/audit_logs.csv"):
    # RDS 연동 or CSV 사용
    if use_rds:
        print("RDS 데이터 로드")
        try:
            df = fetch_audit_logs()
            if df.empty:
                if os.path.exists(csv_path):
                    print("RDS 데이터 없음 → CSV 더미 데이터로 대체")
                    df = pd.read_csv(csv_path)
                else:
                    raise ValueError("RDS 데이터가 없고 CSV 더미 파일도 없습니다.")
        except Exception:
            if os.path.exists(csv_path):
                print("RDS 조회 실패 → CSV 더미 데이터로 대체")
                df = pd.read_csv(csv_path)
            else:
                raise
    else:
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV 파일이 없습니다: {csv_path}")
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

    model = load_model()
    features_df["score"] = model.predict(X)

    features_df[["risk_level", "reason"]] = features_df.apply(
        classify_risk, axis=1, result_type="expand"
    )

    # RDS 데이터는 성능 검증 생략
    if not use_rds:
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
    train_and_save()
    train_and_predict()