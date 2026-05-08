from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from model import train_and_predict
from datetime import datetime
from schemas import AlertResponse, Alert

app = FastAPI()

# CORS 설정 (프론트 연동용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "MediBook AI 서버 정상 동작 중"}

@app.get("/ai/alerts", response_model=AlertResponse)
def get_alerts():
    # 모델 실행
    df = train_and_predict()
    
    # 이상 유저만 필터링
    result = df[df["risk_level"] != "NORMAL"]
    
    alerts = []
    for _, row in result.iterrows():
        alerts.append({
            "user_id": int(row["user_id"]),
            "risk_level": row["risk_level"],
            "requests_per_min": round(row["requests_per_min"], 2),
            "login_fail_count": int(row["login_fail_count"]),
            "forbidden_ratio": round(row["forbidden_ratio"], 2),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return {"count": len(alerts), "alerts": alerts}