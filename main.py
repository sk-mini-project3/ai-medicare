from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from model import train_and_predict, retrain_model
from datetime import datetime
from schemas import AlertResponse, Alert, AnalyzeRequest, AnalyzeResponse, TrainResponse
from notifier import send_alert_email

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

    # 이메일 알림 발송
    send_alert_email([a.dict() for a in alerts])

    return AlertResponse(count=len(alerts), alerts=alerts)


@app.post("/ai/analyze", response_model=AnalyzeResponse)
def analyze_user(request: AnalyzeRequest, use_rds: bool = False):
    try:
        df = train_and_predict(use_rds=use_rds)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"모델 실행 오류: {str(e)}")

    user_result = df[df["user_id"] == request.user_id]

    if user_result.empty:
        raise HTTPException(
            status_code=404,
            detail=f"user_id {request.user_id} 에 해당하는 데이터가 없습니다.",
        )

    row = user_result.iloc[0]

    return AnalyzeResponse(
        user_id=int(row["user_id"]),
        risk_level=row["risk_level"],
        reason=row["reason"] if row["reason"] else "정상 접근 패턴",
        requests_per_min=round(row["requests_per_min"], 2),
        login_fail_count=int(row["login_fail_count"]),
        forbidden_ratio=round(row["forbidden_ratio"], 2),
        unique_endpoints=int(row["unique_endpoints"]),
        top_ip_ratio=round(row["top_ip_ratio"], 2),
        avg_hour=round(row["avg_hour"], 1),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.post("/ai/train", response_model=TrainResponse)
def train_model():
    try:
        result = retrain_model()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"재학습 오류: {str(e)}")

    return TrainResponse(
        message="모델 재학습 완료",
        row_count=result["row_count"],
        user_count=result["user_count"],
        elapsed_sec=result["elapsed_sec"],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )