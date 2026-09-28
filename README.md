# 우리집 가계부 (가족용)
환경변수 3개가 필요합니다.
- DATABASE_URL : Railway Postgres 연결 주소 (예: ${{Postgres.DATABASE_URL}})
- APP_PASSWORD : 가족 공용 비밀번호
- SESSION_SECRET : 로그인 유지용 긴 임의 문자열 (32자 이상)
시작 명령: npm start
