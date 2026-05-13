from pydantic import BaseModel
from typing import List, Optional

# 개별 알림 형식
class Alert(BaseModel):
    user_id: int
    risk_level: str        # HIGH / MEDIUM / NORMAL
    requests_per_min: float
    login_fail_count: int
    forbidden_ratio: float
    reason: str
    timestamp: str

# 전체 응답 형식
class AlertResponse(BaseModel):
    count: int
    alerts: List[Alert]

# 분석 요청 형식
class AnalyzeRequest(BaseModel):
    user_id: int

# 단일 유저 분석 응답 형식
class AnalyzeResponse(BaseModel):
    user_id: int
    risk_level: str                  # HIGH / MEDIUM / NORMAL / UNKNOWN
    reason: str
    requests_per_min: float
    login_fail_count: int
    forbidden_ratio: float
    unique_endpoints: Optional[int] = None
    top_ip_ratio: Optional[float] = None
    avg_hour: Optional[float] = None
    timestamp: str

# 재학습 응답 형식
class TrainResponse(BaseModel):
    message: str
    row_count: int       # 학습에 사용된 로그 건수
    user_count: int      # 학습에 사용된 유저 수
    elapsed_sec: float   # 소요 시간(초)
    timestamp: str