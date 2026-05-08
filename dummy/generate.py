def generate_new_attack_logs():
    """
    모델이 학습한 적 없는 새로운 공격 패턴
    """
    logs = []
    
    # 새로운 공격 1: 새벽 시간대 처방전 대량 조회 (내부자 위협)
    base_time = datetime.now() - timedelta(days=1)
    for i in range(30):
        logs.append({
            "user_id": 97,
            "endpoint": "/api/v1/prescriptions",
            "method": "GET",
            "ip": "192.168.1.100",
            "status_code": 200,
            "timestamp": base_time.replace(hour=3) + timedelta(minutes=i)
        })
    
    # 새로운 공격 2: 여러 계정을 같은 IP로 접근 (계정 공유 의심)
    for user in [101, 102, 103]:
        for i in range(5):
            logs.append({
                "user_id": user,
                "endpoint": "/api/v1/reservations",
                "method": "GET",
                "ip": "10.10.10.10",  # 같은 IP
                "status_code": 200,
                "timestamp": datetime.now() - timedelta(minutes=i*2)
            })
    
    return logs

if __name__ == "__main__":
    normal = generate_normal_logs(500)
    attack = generate_attack_logs(50)
    new_attack = generate_new_attack_logs()
    
    all_logs = normal + attack + new_attack
    df = pd.DataFrame(all_logs)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df.to_csv("dummy/audit_logs.csv", index=False)
    print(f"더미 데이터 생성 완료: {len(df)}건")
    print(f"정상 로그: {len(normal)}건")
    print(f"기존 공격 로그: {len(attack)}건")
    print(f"새로운 공격 로그: {len(new_attack)}건")