# App 16(AWS 보안그룹)·App 18(AWS IAM 감사기) 실습용 — LocalStack에 의도적으로 취약한
# IAM/보안그룹 리소스를 실제 aws CLI로 생성해두는 컨테이너. 공식 amazon/aws-cli 이미지 위에
# 시드 스크립트만 얹는다(bad-firewall 컨테이너와 동일한 패턴).
FROM amazon/aws-cli:2.17.62

COPY seed.sh /seed.sh
USER root
RUN chmod +x /seed.sh
ENTRYPOINT ["/seed.sh"]
