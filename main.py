from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from model import train_and_predict
from datetime import datetime
from schemas import AlertResponse, Alert
from notifier import send_alert_email
from schemas import AlertResponse, Alert, AnalyzeRequest

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
def get_alerts(use_rds: bool = False):
    df = train_and_predict(use_rds=use_rds)
    result = df[df["risk_level"] != "NORMAL"]

    alerts = [
        Alert(
            user_id=int(row["user_id"]),
            risk_level=row["risk_level"],
            requests_per_min=round(row["requests_per_min"], 2),
            login_fail_count=int(row["login_fail_count"]),
            forbidden_ratio=round(row["forbidden_ratio"], 2),
            reason=row["reason"],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        for _, row in result.iterrows()
    ]

    # 이메일 알림 발송 추가
    send_alert_email([a.dict() for a in alerts])

    return AlertResponse(count=len(alerts), alerts=alerts)


@app.post("/ai/analyze")
def analyze_user(request: AnalyzeRequest):
    df = train_and_predict()

    user_result = df[df["user_id"] == request.user_id]

    if user_result.empty:
        return {
            "user_id": request.user_id,
            "risk_level": "UNKNOWN",
            "reason": "데이터 없음",
        }

    row = user_result.iloc[0]
    return {
        "user_id": int(row["user_id"]),
        "risk_level": row["risk_level"],
        "reason": row["reason"],
        "requests_per_min": round(row["requests_per_min"], 2),
        "login_fail_count": int(row["login_fail_count"]),
        "forbidden_ratio": round(row["forbidden_ratio"], 2),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
