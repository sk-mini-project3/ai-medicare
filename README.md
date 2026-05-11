# 🏥 Medicare AI 서버

의료 예약 플랫폼 **Medicare**의 AI 이상 탐지 서버입니다.
서버 접근 로그를 분석해 비정상적인 접근 패턴을 자동으로 탐지하고 경고합니다.

---

## 📌 주요 기능

- 서버 접근 로그(AuditLog) 기반 이상 행위 탐지
- Isolation Forest 모델로 비정상 접근 패턴 분류
- 탐지 결과 API 제공 (`/ai/alerts`)
- 공격 탐지율 96% (KDD Cup 1999 데이터셋 기준)

---

## 🛠 기술 스택

| 항목 | 기술 |
|------|------|
| Language | Python 3.11 |
| Framework | FastAPI |
| ML | scikit-learn (Isolation Forest) |
| Data | pandas |
| DB 연결 | SQLAlchemy + psycopg2 |
| 서버 실행 | uvicorn |

---

## 📁 프로젝트 구조

```
ai-medicare/
├── main.py          # FastAPI 서버
├── model.py         # Isolation Forest 모델
├── features.py      # 피처 추출
├── database.py      # RDS 연결
├── schemas.py       # API 응답 형식
├── notifier.py      # 이메일 알림
├── requirements.txt
├── Dockerfile
└── dummy/
    ├── generate.py      # 더미 데이터 생성
    └── convert_kdd.py   # KDD 데이터 변환
```

---

## ⚙️ 실행 방법

### 로컬 실행

```bash
# 가상환경 생성 및 활성화
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac

# 패키지 설치
pip install -r requirements.txt

# 서버 실행
uvicorn main:app --reload --port 8001
```

### Docker 실행

```bash
docker build -t ai-medicare .
docker run -p 8001:8001 ai-medicare
```

---

## 📡 API 명세

### GET /ai/alerts
이상 탐지된 유저 목록 반환

**Response**
```json
{
  "count": 2,
  "alerts": [
    {
      "user_id": 99,
      "risk_level": "HIGH",
      "requests_per_min": 51.43,
      "login_fail_count": 0,
      "forbidden_ratio": 0.5,
      "timestamp": "2026-05-08 09:40:16"
    }
  ]
}
```

---

## 🤖 탐지 시나리오

| 시나리오 | 탐지 기준 | 위험 등급 |
|----------|-----------|-----------|
| IDOR 시도 | forbidden_ratio 30% 이상 | HIGH |
| 무차별 로그인 | 로그인 실패 5회 이상 | HIGH |
| 새벽 대량 접근 | 평균 시간대 5시 이하 | HIGH |
| 비정상 요청 빈도 | 분당 요청 5회 이상 | HIGH |

---

---
## 📧 이메일 알림

이상 행위 탐지 시 관리자 이메일로 자동 발송됩니다.

`.env` 파일에 아래 내용 설정 필요

EMAIL_ADDRESS=발송용Gmail주소
EMAIL_PASSWORD=앱비밀번호
ADMIN_EMAIL=수신할이메일주소
---