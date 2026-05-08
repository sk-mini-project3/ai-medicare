# Python 3.11 베이스 이미지
FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# 패키지 먼저 설치 (캐시 활용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스코드 복사
COPY . .

# 포트 오픈
EXPOSE 8001

# 서버 실행
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]