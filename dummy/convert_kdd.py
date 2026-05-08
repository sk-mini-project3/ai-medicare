import pandas as pd
import random
from datetime import datetime, timedelta

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label"
]

def convert_kdd_to_auditlog(filepath: str, output_path: str):
    print("KDD 데이터 로드")
    df = pd.read_csv(filepath, header=None, names=columns)
    
    print(f"전체 데이터: {len(df)}건")
    
    normal_df = df[df["label"] == "normal."].sample(n=500, random_state=42)
    attack_df = df[df["label"] != "normal."].sample(n=100, random_state=42)
    
    print(f"정상 샘플: {len(normal_df)}건")
    print(f"공격 샘플: {len(attack_df)}건")
    
    def convert_row(row, user_id, is_attack):
        service_map = {
            "http":  "/api/v1/reservations",
            "ftp":   "/api/v1/prescriptions",
            "smtp":  "/api/v1/medical-records",
            "ssh":   "/api/v1/auth/login",
        }
        endpoint = service_map.get(row["service"], "/api/v1/reservations")
        
        # 시간대: 공격이면 새벽 포함
        if is_attack and row["serror_rate"] > 0.5:
            hour = random.randint(2, 4)
        elif is_attack:
            hour = random.choice([random.randint(2, 4), random.randint(8, 22)])
        else:
            hour = random.randint(8, 22)
        
        timestamp = datetime.now() - timedelta(
            days=random.randint(0, 30),
            hours=hour,
            minutes=random.randint(0, 59)
        )
        
        # status_code 결정 (KDD 피처 활용)
        if row["num_failed_logins"] > 0:
            status_code = 401
        elif is_attack and row["rerror_rate"] > 0.5:
            status_code = 403
        elif is_attack and row["serror_rate"] > 0.5:
            status_code = 400
        else:
            status_code = 200
        
        # 분당 요청 수 반영 (count 컬럼 활용)
        requests_per_min = row["count"] / max(row["duration"], 1)
        
        return {
            "user_id": user_id,
            "endpoint": endpoint,
            "method": "POST" if "login" in endpoint else "GET",
            "ip": f"192.168.{random.randint(1,10)}.{random.randint(1,50)}",
            "status_code": status_code,
            "timestamp": timestamp,
            # KDD 추가 피처
            "serror_rate": round(row["serror_rate"], 4),
            "rerror_rate": round(row["rerror_rate"], 4),
            "num_failed_logins": int(row["num_failed_logins"]),
            "count": int(row["count"]),
            "diff_srv_rate": round(row["diff_srv_rate"], 4),
        }
    
    logs = []
    for i, (_, row) in enumerate(normal_df.iterrows()):
        logs.append(convert_row(row, user_id=i+1, is_attack=False))
    for i, (_, row) in enumerate(attack_df.iterrows()):
        logs.append(convert_row(row, user_id=900+i, is_attack=True))
    
    result_df = pd.DataFrame(logs)
    result_df = result_df.sort_values("timestamp").reset_index(drop=True)
    result_df.to_csv(output_path, index=False)
    
    print(f"\n변환 완료: {len(result_df)}건")
    print(result_df.head())

if __name__ == "__main__":
    convert_kdd_to_auditlog(
        filepath="dummy/kddcup.data_10_percent_corrected",
        output_path="dummy/audit_logs.csv"
    )