import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")


def send_alert_email(alerts: list):
    if not alerts:
        return

    # 이메일 내용 작성
    body = "🚨 Medicare 보안 경고 - 이상 접근 탐지\n\n"
    body += f"탐지된 이상 유저: {len(alerts)}명\n"
    body += "=" * 50 + "\n\n"

    for alert in alerts:
        body += f"👤 user_id: {alert['user_id']}\n"
        body += f"⚠️  위험 등급: {alert['risk_level']}\n"
        body += f"📋 탐지 사유: {alert['reason']}\n"
        body += f"📊 분당 요청: {alert['requests_per_min']}회\n"
        body += f"🔐 로그인 실패: {alert['login_fail_count']}회\n"
        body += f"🚫 403 비율: {alert['forbidden_ratio']}\n"
        body += f"🕐 시간: {alert['timestamp']}\n"
        body += "-" * 30 + "\n\n"

    # 이메일 구성
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = ADMIN_EMAIL
    msg["Subject"] = f"[Medicare 보안 경고] 이상 접근 {len(alerts)}건 탐지"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # 발송
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.sendmail(EMAIL_ADDRESS, ADMIN_EMAIL, msg.as_string())
            print(f"✅ 이메일 발송 완료 → {ADMIN_EMAIL}")
    except Exception as e:
        print(f"❌ 이메일 발송 실패: {e}")


if __name__ == "__main__":
    # 테스트 발송
    test_alerts = [
        {
            "user_id": 99,
            "risk_level": "HIGH",
            "reason": "403 에러 비율 50%, 분당 요청 51.4회",
            "requests_per_min": 51.43,
            "login_fail_count": 0,
            "forbidden_ratio": 0.5,
            "timestamp": "2026-05-11 09:40:00"
        }
    ]
    send_alert_email(test_alerts)