_PLANS = {
    "ransomware": {
        "summary": "랜섬웨어가 탐지됐습니다. 즉각적인 네트워크 격리와 백업 검증이 최우선입니다. 절대 몸값을 지불하지 마세요.",
        "estimated_time": "24~72시간",
        "key_contacts": ["보안팀(CISO)", "IT 인프라팀", "경영진", "법무팀", "사이버 보험사"],
        "phases": [
            {
                "id": "immediate",
                "name": "즉시 조치",
                "timeframe": "0 ~ 1시간",
                "color": "red",
                "steps": [
                    "감염된 시스템을 네트워크에서 즉시 물리적으로 격리 (LAN 케이블 분리, Wi-Fi 차단)",
                    "감염 범위 파악: 암호화된 파일 확장자·랜섬노트 위치 확인",
                    "CISO 및 경영진에 즉시 보고",
                    "사이버 보험사에 사고 신고",
                    "백업 서버가 감염됐는지 확인 후 즉시 격리",
                    "절대 몸값을 지불하지 않음 (복호화 보장 없음)",
                ],
            },
            {
                "id": "investigation",
                "name": "조사",
                "timeframe": "1 ~ 4시간",
                "color": "orange",
                "steps": [
                    "감염 시작점(Patient Zero) 식별: 이메일·USB·RDP 등 침투 경로 분석",
                    "EDR/SIEM 로그에서 최초 실행 시간·프로세스 트리 확인",
                    "C2(Command & Control) 서버 IP/도메인 식별 및 방화벽 차단",
                    "랜섬웨어 종류 식별 (ID Ransomware 서비스 활용)",
                    "감염 시스템 목록 작성 및 피해 규모 산정",
                    "포렌식 증거 보전: 메모리 덤프, 이벤트 로그 수집",
                ],
            },
            {
                "id": "containment",
                "name": "봉쇄",
                "timeframe": "4 ~ 8시간",
                "color": "yellow",
                "steps": [
                    "확산 방지: 네트워크 세그먼트 차단, 횡적 이동 경로 봉쇄",
                    "감염 의심 계정 비밀번호 즉시 초기화 및 MFA 강제 적용",
                    "공유 폴더·클라우드 스토리지 쓰기 권한 일시 차단",
                    "미감염 시스템 백업 즉시 실행",
                    "외부 공개 서비스(웹·메일) 일시 중단 검토",
                ],
            },
            {
                "id": "eradication",
                "name": "제거",
                "timeframe": "8 ~ 24시간",
                "color": "purple",
                "steps": [
                    "감염 시스템 포맷 후 클린 이미지로 재설치 (치료 시도 지양)",
                    "악성코드 침투에 사용된 취약점 패치",
                    "침투 경로(피싱 메일·취약 RDP 등) 완전 차단",
                    "전체 네트워크 악성코드 스캔",
                    "변경된 계정 권한·백도어 계정 확인 및 삭제",
                ],
            },
            {
                "id": "recovery",
                "name": "복구",
                "timeframe": "1 ~ 7일",
                "color": "blue",
                "steps": [
                    "검증된 최신 백업에서 데이터 복원",
                    "복원된 시스템 보안 검증 후 순차적으로 네트워크 재연결",
                    "업무 연속성 계획(BCP)에 따라 핵심 서비스 우선 복구",
                    "사용자 계정 재발급 및 비밀번호 전체 초기화",
                    "복구 완료 시스템 모니터링 강화 (72시간)",
                ],
            },
            {
                "id": "postmortem",
                "name": "사후 조치",
                "timeframe": "복구 완료 후",
                "color": "green",
                "steps": [
                    "전체 사고 타임라인 문서화 및 보고서 작성",
                    "규제 기관·개인정보보호위원회 신고 (해당 시)",
                    "침투 경로별 재발 방지 대책 수립",
                    "백업 정책 및 오프라인 백업 체계 강화",
                    "임직원 랜섬웨어 예방 교육 실시",
                    "사이버 보험 청구 절차 진행",
                ],
            },
        ],
    },
    "data_breach": {
        "summary": "데이터 유출 사고입니다. 유출 범위 파악과 법적 신고 의무 이행이 최우선입니다.",
        "estimated_time": "72시간 ~ 2주",
        "key_contacts": ["CISO", "법무팀", "개인정보보호 담당자", "PR팀", "규제 기관"],
        "phases": [
            {
                "id": "immediate",
                "name": "즉시 조치",
                "timeframe": "0 ~ 2시간",
                "color": "red",
                "steps": [
                    "유출 경로 즉시 차단 (취약한 API·DB 접근 권한 차단)",
                    "유출된 데이터 종류·건수·대상 초기 파악",
                    "CISO·법무팀·경영진에 즉시 보고",
                    "사고 대응팀(CERT) 구성 및 소집",
                    "추가 유출 방지를 위한 임시 접근 통제 강화",
                ],
            },
            {
                "id": "investigation",
                "name": "조사",
                "timeframe": "2 ~ 24시간",
                "color": "orange",
                "steps": [
                    "유출 경로 정밀 분석: SQL Injection·API 키 노출·내부자 유출 여부",
                    "접근 로그·DB 쿼리 로그 분석으로 유출 데이터 특정",
                    "유출 데이터가 다크웹에 게시됐는지 모니터링",
                    "피해 당사자 식별 (개인정보 포함 여부 확인)",
                    "포렌식 증거 보전",
                ],
            },
            {
                "id": "containment",
                "name": "봉쇄 및 법적 대응",
                "timeframe": "24 ~ 72시간",
                "color": "yellow",
                "steps": [
                    "개인정보보호위원회에 72시간 내 신고 (개인정보보호법 의무)",
                    "유출 당사자에게 통지 계획 수립",
                    "법적 책임 범위 검토 (법무팀)",
                    "언론 대응 메시지 준비 (PR팀)",
                    "유출된 자격증명 강제 초기화",
                ],
            },
            {
                "id": "eradication",
                "name": "취약점 제거",
                "timeframe": "3 ~ 7일",
                "color": "purple",
                "steps": [
                    "유출 원인 취약점 패치 및 코드 수정",
                    "전체 API 키·시크릿 교체",
                    "DB 접근 권한 최소 권한 원칙으로 재설정",
                    "데이터 암호화 강화 (저장·전송 모두)",
                ],
            },
            {
                "id": "recovery",
                "name": "복구 및 피해자 지원",
                "timeframe": "1 ~ 2주",
                "color": "blue",
                "steps": [
                    "피해자 통지 및 지원 방안 제공 (신용 모니터링 등)",
                    "공식 사과문 및 재발 방지 대책 발표",
                    "서비스 보안 강화 후 재개",
                ],
            },
            {
                "id": "postmortem",
                "name": "사후 조치",
                "timeframe": "복구 완료 후",
                "color": "green",
                "steps": [
                    "전체 사고 보고서 작성 및 내부 공유",
                    "데이터 분류 체계 및 접근 통제 정책 재수립",
                    "정기적인 취약점 스캔·침투 테스트 도입",
                    "개인정보 처리 프로세스 전면 감사",
                ],
            },
        ],
    },
    "ddos": {
        "summary": "DDoS 공격이 탐지됐습니다. ISP와 협력해 트래픽을 필터링하고 서비스 가용성을 회복하는 것이 목표입니다.",
        "estimated_time": "1 ~ 24시간",
        "key_contacts": ["ISP/통신사 NOC", "CDN 업체(Cloudflare 등)", "인프라팀", "경영진"],
        "phases": [
            {
                "id": "immediate",
                "name": "즉시 조치",
                "timeframe": "0 ~ 30분",
                "color": "red",
                "steps": [
                    "DDoS 공격 유형 식별: 볼류메트릭·프로토콜·애플리케이션 레이어",
                    "ISP에 긴급 연락, 업스트림 필터링 요청",
                    "CDN/DDoS 방어 서비스 즉시 활성화 (Cloudflare 등)",
                    "공격 트래픽 소스 IP 대역 방화벽 차단",
                    "Rate Limiting 즉시 강화",
                ],
            },
            {
                "id": "investigation",
                "name": "분석",
                "timeframe": "30분 ~ 2시간",
                "color": "orange",
                "steps": [
                    "공격 트래픽 패턴 분석 (패킷 크기·프로토콜·소스 분포)",
                    "봇넷 C2 서버 식별 및 블랙리스트 등록",
                    "공격 목적 파악 (경쟁사·핵티비스트·협박)",
                    "내부 서버 리소스(CPU·메모리·대역폭) 임계값 모니터링",
                ],
            },
            {
                "id": "containment",
                "name": "완화",
                "timeframe": "1 ~ 4시간",
                "color": "yellow",
                "steps": [
                    "Anycast 네트워크로 트래픽 분산",
                    "지리적 IP 차단 (공격 소스 국가 차단 검토)",
                    "WAF 규칙 추가로 악성 요청 필터링",
                    "핵심 서비스 우선 복구, 비핵심 서비스 일시 중단",
                    "트래픽 스크러빙 센터 활용",
                ],
            },
            {
                "id": "recovery",
                "name": "복구",
                "timeframe": "공격 완화 후",
                "color": "blue",
                "steps": [
                    "트래픽 정상화 확인 후 서비스 순차 복구",
                    "서버 리소스 정상 수준 복귀 확인",
                    "차단 규칙 유지하며 재공격 모니터링 (48시간)",
                ],
            },
            {
                "id": "postmortem",
                "name": "사후 조치",
                "timeframe": "복구 완료 후",
                "color": "green",
                "steps": [
                    "공격 타임라인·대응 과정 문서화",
                    "DDoS 방어 아키텍처 개선 (CDN 상시 활성화 등)",
                    "ISP와 긴급 대응 SLA 재협의",
                    "BCP(업무연속성계획) 업데이트",
                ],
            },
        ],
    },
    "phishing": {
        "summary": "피싱 공격이 탐지됐습니다. 피해 확산 방지와 자격증명 침해 범위 파악이 핵심입니다.",
        "estimated_time": "4 ~ 24시간",
        "key_contacts": ["보안팀", "IT팀", "HR팀(임직원 통지)", "이메일 서비스 제공사"],
        "phases": [
            {
                "id": "immediate",
                "name": "즉시 조치",
                "timeframe": "0 ~ 1시간",
                "color": "red",
                "steps": [
                    "피싱 메일 수신자 전체 파악 및 메일 즉시 회수(Recall)",
                    "피싱 도메인·URL DNS 차단 (내부 DNS 블랙리스트 등록)",
                    "링크 클릭·첨부파일 실행 여부 확인",
                    "자격증명 입력 가능성 있는 계정 즉시 비밀번호 초기화",
                    "전 임직원에게 피싱 메일 주의 공지 발송",
                ],
            },
            {
                "id": "investigation",
                "name": "조사",
                "timeframe": "1 ~ 4시간",
                "color": "orange",
                "steps": [
                    "피싱 메일 헤더 분석으로 발신 경로·IP 파악",
                    "클릭한 직원의 시스템에서 악성코드 감염 여부 스캔",
                    "자격증명 유출 여부 확인: 비정상 로그인 시도 검토",
                    "피싱 킷 호스팅 서버 신고 (Google Safe Browsing 등)",
                    "동일 캠페인의 다른 피싱 메일 존재 여부 확인",
                ],
            },
            {
                "id": "containment",
                "name": "봉쇄",
                "timeframe": "2 ~ 8시간",
                "color": "yellow",
                "steps": [
                    "침해된 계정 세션 강제 종료 및 MFA 즉시 활성화",
                    "이메일 필터 규칙 강화 (발신자 도메인·키워드)",
                    "감염 시스템 네트워크 격리",
                    "OAuth 토큰·앱 권한 검토 및 의심 앱 해제",
                ],
            },
            {
                "id": "eradication",
                "name": "제거",
                "timeframe": "4 ~ 12시간",
                "color": "purple",
                "steps": [
                    "감염 시스템 악성코드 완전 제거 또는 재설치",
                    "유출된 자격증명으로 생성된 백도어 계정 삭제",
                    "침투에 사용된 취약점 패치",
                ],
            },
            {
                "id": "recovery",
                "name": "복구",
                "timeframe": "12 ~ 24시간",
                "color": "blue",
                "steps": [
                    "계정 복구 및 새 비밀번호 설정 지원",
                    "영향받은 서비스 모니터링 강화",
                    "사용자 보안 인식 교육 즉시 실시",
                ],
            },
            {
                "id": "postmortem",
                "name": "사후 조치",
                "timeframe": "복구 완료 후",
                "color": "green",
                "steps": [
                    "피싱 시뮬레이션 훈련 강화",
                    "이메일 보안 솔루션(DMARC·DKIM·SPF) 점검",
                    "전사 MFA 의무화 검토",
                    "사고 보고서 작성 및 경영진 보고",
                ],
            },
        ],
    },
    "malware": {
        "summary": "악성코드 감염이 탐지됐습니다. 감염 시스템 격리와 횡적 이동 차단이 우선입니다.",
        "estimated_time": "12 ~ 48시간",
        "key_contacts": ["보안팀", "IT팀", "경영진"],
        "phases": [
            {
                "id": "immediate",
                "name": "즉시 조치",
                "timeframe": "0 ~ 1시간",
                "color": "red",
                "steps": [
                    "감염 시스템 네트워크 즉시 격리",
                    "악성코드 종류 초기 식별 (EDR 경보·바이러스 백신 로그)",
                    "감염 범위 파악: 동일 네트워크 세그먼트 스캔",
                    "보안팀·IT팀 즉시 소집",
                ],
            },
            {
                "id": "investigation",
                "name": "조사",
                "timeframe": "1 ~ 6시간",
                "color": "orange",
                "steps": [
                    "악성코드 샘플 추출 후 분석 (VirusTotal·샌드박스)",
                    "침투 경로 역추적: 이메일·웹·USB·취약점",
                    "C2 통신 IP·도메인 식별 및 차단",
                    "레지스트리·시작프로그램·예약작업 악성 항목 확인",
                    "포렌식 증거 보전",
                ],
            },
            {
                "id": "containment",
                "name": "봉쇄",
                "timeframe": "4 ~ 12시간",
                "color": "yellow",
                "steps": [
                    "C2 서버 방화벽 차단",
                    "감염 경로에 사용된 계정 비밀번호 초기화",
                    "취약한 시스템 임시 오프라인 전환",
                    "전체 네트워크 악성코드 스캔 실행",
                ],
            },
            {
                "id": "eradication",
                "name": "제거",
                "timeframe": "6 ~ 24시간",
                "color": "purple",
                "steps": [
                    "감염 시스템 클린 이미지로 재설치",
                    "악성코드 침투에 사용된 취약점 패치",
                    "백도어·지속성 메커니즘 완전 제거 확인",
                ],
            },
            {
                "id": "recovery",
                "name": "복구",
                "timeframe": "1 ~ 3일",
                "color": "blue",
                "steps": [
                    "검증된 백업에서 데이터 복원",
                    "복구 시스템 보안 검증 후 네트워크 재연결",
                    "72시간 집중 모니터링",
                ],
            },
            {
                "id": "postmortem",
                "name": "사후 조치",
                "timeframe": "복구 완료 후",
                "color": "green",
                "steps": [
                    "사고 보고서 작성",
                    "패치 관리 프로세스 강화",
                    "엔드포인트 보안 솔루션(EDR) 도입 검토",
                    "임직원 보안 교육 실시",
                ],
            },
        ],
    },
    "insider_threat": {
        "summary": "내부자 위협이 의심됩니다. 법적 절차를 준수하면서 증거를 보전하고 피해를 최소화해야 합니다.",
        "estimated_time": "48시간 ~ 수주",
        "key_contacts": ["CISO", "HR팀", "법무팀", "경영진", "수사 기관(필요 시)"],
        "phases": [
            {
                "id": "immediate",
                "name": "즉시 조치",
                "timeframe": "0 ~ 2시간",
                "color": "red",
                "steps": [
                    "CISO·HR·법무팀에 즉시 보고 (비밀 유지)",
                    "의심 직원 계정 접근 권한 조용히 축소 (인지시키지 않음)",
                    "증거 보전 시작: 로그·이메일·접근 기록 즉시 수집",
                    "법무팀과 법적 대응 절차 협의",
                ],
            },
            {
                "id": "investigation",
                "name": "조사",
                "timeframe": "2 ~ 48시간",
                "color": "orange",
                "steps": [
                    "DLP(데이터 유출 방지) 로그에서 이상 데이터 전송 확인",
                    "접근 로그: 비정상적인 시간대·대량 다운로드 여부",
                    "이메일·메신저 로그 분석 (법적 허용 범위 내)",
                    "USB·클라우드 업로드 이력 확인",
                    "포렌식 전문가 투입 검토",
                ],
            },
            {
                "id": "containment",
                "name": "봉쇄",
                "timeframe": "조사 결과에 따라",
                "color": "yellow",
                "steps": [
                    "확인 시: 해당 직원 계정 완전 차단 및 접근 디바이스 회수",
                    "유출된 데이터 피해 범위 산정",
                    "외부 공모자 여부 확인",
                    "HR 절차에 따라 징계/해고 진행",
                ],
            },
            {
                "id": "eradication",
                "name": "피해 제거",
                "timeframe": "1 ~ 2주",
                "color": "purple",
                "steps": [
                    "유출된 정보의 회수 또는 사용 차단 조치",
                    "법적 조치 (민형사 소송·수사 기관 신고) 검토",
                    "해당 직원이 생성한 백도어·계정 완전 제거",
                ],
            },
            {
                "id": "recovery",
                "name": "복구",
                "timeframe": "2 ~ 4주",
                "color": "blue",
                "steps": [
                    "피해 범위 공개 여부 결정 (법무팀 협의)",
                    "영향받은 고객·파트너 통지 (필요 시)",
                    "업무 프로세스 정상화",
                ],
            },
            {
                "id": "postmortem",
                "name": "사후 조치",
                "timeframe": "복구 완료 후",
                "color": "green",
                "steps": [
                    "내부자 위협 탐지 정책 강화",
                    "최소 권한 원칙 전면 재검토",
                    "퇴직자·전직자 계정 즉시 비활성화 프로세스 수립",
                    "직원 보안 서약서 및 교육 강화",
                ],
            },
        ],
    },
}

_CHAT_REPLIES = {
    "ransomware": [
        "랜섬웨어 대응 시 가장 중요한 것은 백업입니다. 오프라인 백업이 있다면 복호화 키 없이도 복구가 가능합니다. 백업의 무결성을 먼저 검증하세요.",
        "몸값 지불은 권장하지 않습니다. 실제 복호화 키를 제공하는 비율은 약 65%에 불과하며, 지불 시 추가 공격 대상이 될 수 있습니다.",
        "랜섬웨어 종류를 'ID Ransomware' 웹사이트에서 확인하면 무료 복호화 도구가 있는지 알 수 있습니다.",
    ],
    "data_breach": [
        "개인정보보호법상 개인정보 유출 시 72시간 내 개인정보보호위원회에 신고해야 합니다. 신고를 지연하면 추가 과징금이 부과될 수 있습니다.",
        "유출 데이터가 다크웹에 게시됐는지 'Have I Been Pwned' 같은 서비스로 모니터링하세요.",
        "피해자 통지 시 구체적인 유출 내용·일시·조치 사항을 포함해야 신뢰 회복에 도움이 됩니다.",
    ],
    "ddos": [
        "DDoS 공격 중 CDN을 통한 트래픽 분산이 가장 효과적입니다. Cloudflare Magic Transit 같은 서비스를 즉시 활성화하세요.",
        "공격이 장기화될 경우 ISP에 BGP Blackhole 라우팅을 요청하면 공격 트래픽을 업스트림에서 차단할 수 있습니다.",
        "애플리케이션 레이어 DDoS(L7)는 Rate Limiting + CAPTCHA + WAF 조합으로 대응하세요.",
    ],
    "phishing": [
        "피싱 메일을 받은 모든 직원의 자격증명을 일괄 초기화하는 것이 안전합니다. 클릭 여부를 모두 확인하기 어렵습니다.",
        "DMARC p=reject 정책을 설정하면 사칭 이메일이 수신자에게 전달되는 것을 차단할 수 있습니다.",
        "구글 세이프 브라우징(Google Safe Browsing)에 피싱 URL을 신고하면 빠르게 차단됩니다.",
    ],
    "malware": [
        "EDR 솔루션이 있다면 감염 시스템의 프로세스 트리를 확인해 최초 실행 파일과 부모 프로세스를 추적하세요.",
        "악성코드 샘플은 VirusTotal에 업로드하면 70개 이상의 백신 엔진으로 즉시 분석 결과를 얻을 수 있습니다.",
        "감염 시스템을 치료하려 하지 말고 재설치하는 것이 완전한 제거를 보장합니다.",
    ],
    "insider_threat": [
        "내부자 조사 시 법적 절차를 반드시 준수해야 합니다. 무단 개인 이메일·디바이스 열람은 법적 문제가 될 수 있습니다.",
        "의심 직원에게 조사 사실을 알리기 전에 증거를 먼저 확보하세요. 인지 후 증거 인멸 위험이 있습니다.",
        "DLP(Data Loss Prevention) 솔루션 도입으로 향후 내부자 위협을 사전에 탐지할 수 있습니다.",
    ],
}

_DEFAULT_REPLY = "해당 질문은 사고 유형과 환경에 따라 다릅니다. 보안 전문가 또는 사고 대응 전문 업체(DFIR)에 문의하는 것을 권장합니다."


def generate_mock_plan(incident_type: str, severity: str, description: str) -> dict:
    plan = _PLANS.get(incident_type, _PLANS["malware"])
    return {
        "incident_type": incident_type,
        "severity": severity,
        "description": description,
        **plan,
        "_mock": True,
    }


def generate_mock_chat(incident_type: str, message: str) -> str:
    replies = _CHAT_REPLIES.get(incident_type, [_DEFAULT_REPLY])
    idx = len(message) % len(replies)
    return replies[idx]
