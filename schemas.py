from pydantic import BaseModel
from typing import List

# 개별 알림 형식
class Alert(BaseModel):
    user_id: int
    risk_level: str        # HIGH / MEDIUM / NORMAL
    requests_per_min: float
    login_fail_count: int
    forbidden_ratio: float
    reason: str            # 추가
    timestamp: str

# 전체 응답 형식
class AlertResponse(BaseModel):
    count: int
    alerts: List[Alert]