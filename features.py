import pandas as pd

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    
    features = []
    
    for user_id, group in df.groupby("user_id"):
        duration = (group["timestamp"].max() - group["timestamp"].min()).seconds / 60 + 1
        requests_per_min = len(group) / duration
        avg_hour = group["timestamp"].dt.hour.mean()
        login_fail = len(group[
            (group["endpoint"] == "/api/v1/auth/login") &
            (group["status_code"] == 401)
        ])
        unique_endpoints = group["endpoint"].nunique()
        top_ip_ratio = group["ip"].value_counts().iloc[0] / len(group)
        forbidden_ratio = len(group[group["status_code"] == 403]) / len(group)
        
        # KDD 추가 피처
        avg_serror = group["serror_rate"].mean() if "serror_rate" in group.columns else 0
        avg_rerror = group["rerror_rate"].mean() if "rerror_rate" in group.columns else 0
        avg_diff_srv = group["diff_srv_rate"].mean() if "diff_srv_rate" in group.columns else 0
        avg_count = group["count"].mean() if "count" in group.columns else 0
        
        features.append({
            "user_id": user_id,
            "requests_per_min": round(requests_per_min, 4),
            "avg_hour": round(avg_hour, 2),
            "login_fail_count": login_fail,
            "unique_endpoints": unique_endpoints,
            "top_ip_ratio": round(top_ip_ratio, 4),
            "forbidden_ratio": round(forbidden_ratio, 4),
            "avg_serror_rate": round(avg_serror, 4),
            "avg_rerror_rate": round(avg_rerror, 4),
            "avg_diff_srv_rate": round(avg_diff_srv, 4),
            "avg_count": round(avg_count, 4),
        })
    
    return pd.DataFrame(features)

if __name__ == "__main__":
    df = pd.read_csv("dummy/audit_logs.csv")
    features_df = extract_features(df)
    print("피처 추출 완료")
    print(features_df.head())