import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import pandas as pd

load_dotenv()

DB_URL = os.getenv("DB_URL")


def get_engine():
    if not DB_URL:
        raise ValueError("DB_URL이 설정되지 않았습니다. .env 파일을 확인해주세요.")
    return create_engine(DB_URL)


def fetch_audit_logs() -> pd.DataFrame:
    """
    RDS AuditLog 테이블에서 데이터를 읽어옵니다.
    """
    engine = get_engine()
    
    query = """
        SELECT 
            user_id,
            endpoint,
            method,
            ip,
            status_code,
            timestamp
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT 10000
    """
    
    with engine.connect() as conn:
        df = pd.read_sql(text(query), conn)
    
    print(f"AuditLog {len(df)}건 로드 완료")
    return df


def test_connection():
    """
    DB 연결 테스트
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("DB 연결 성공!")
        return True
    except Exception as e:
        print(f"DB 연결 실패: {e}")
        return False


if __name__ == "__main__":
    test_connection()