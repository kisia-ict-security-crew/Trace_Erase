# AWS Infrastructure Security Snapshot and Analysis Tool (`cloud_temp`)

> **클라우드 로그 삭제 및 인프라 변경 작업 전후의 AWS 보안 상태를 스냅샷하여 비교 분석하고, Neo4j Graph DB 기반의 영향도 시각화를 제공하는 포렌식/감사 분석 자동화 도구입니다.**

---

## 📌 프로젝트 개요 (Overview)

본 프로젝트는 AWS 클라우드 환경에서 발생할 수 있는 **로그 삭제(CloudTrail 중지/삭제)** 및 **보안 설정 변조(IAM, S3, Security Group 등)** 행위를 추적하고 분석하기 위해 개발되었습니다.

인프라 변경 작업 또는 공격 발생 전(`before`)과 후(`after`)의 AWS 보안 메타데이터를 스냅샷 JSON 형태로 수집하고, 두 스냅샷 간의 차이점(Diff)을 추출 및 정규화하여 **Neo4j 그래프 데이터베이스**에 적재합니다. 이를 통해 리소스 간의 연관 관계와 보안 영향도를 직관적으로 시각화할 수 있습니다.

---

## 🛠 주요 기능 (Key Features)

- **6대 핵심 AWS 서비스 메타데이터 수집 (`collectors/`)**:
  - **IAM**: 사용자, 그룹, 역할, 신뢰 관계, 연결된/인라인 정책 상세 정보
  - **Security Group**: 인바운드/아웃바운드 보안 규칙, 포트 범위, 소스/목적지 CIDR
  - **EC2**: 인스턴스 상태, ENI(네트워크 인터페이스), EBS 볼륨, 태그
  - **S3**: 버킷 정책, 퍼블릭 액세스 차단(Public Access Block), ACL, 서버 측 암호화 설정
  - **VPC**: VPC, 서브넷, 라우트 테이블, 인터넷 게이트웨이(IGW), NACL
  - **CloudTrail**: 추적(Trail) 활성화 상태(`is_logging`), 이벤트 셀렉터 설정
- **병렬 수집 및 안전한 예외 처리 (`snapshot.py`)**:
  - Multi-threading(`ThreadPoolExecutor`)을 활용한 동시 수집 지원
  - `safe_call` 예외 핸들링을 통해 권한 부족(`ClientError`) 발생 시에도 전체 수집 프로세스 유지
- **변경점 추출 및 정규화 (`diff.py`, `normalize_diff.py`)**:
  - `before` 스냅샷과 `after` 스냅샷 간의 리소스 상태 차이점(Diff) 도출
  - Graph DB 적재를 위한 데이터 표준화 및 정규화
- **Neo4j Graph DB 연동 파이프라인 (`diff_to_cypher.py`, `neo4j_loader.py`)**:
  - 정규화된 diff 데이터를 Cypher 쿼리로 자동 변환하여 Neo4j DB 적재
  - 인프라 변경 사항 및 보안 위협 연관 관계 시각화

---

## 📂 프로젝트 구조 (Project Structure)

```text
.
├── collectors/              # AWS 서비스별 메타데이터 수집 모듈
│   ├── iam.py               # IAM 수집기
│   ├── security_group.py    # Security Group 수집기
│   ├── ec2.py               # EC2 수집기
│   ├── s3.py                # S3 수집기
│   ├── vpc.py               # VPC 수집기
│   └── cloudtrail.py        # CloudTrail 수집기
├── docs/                    # 연구 논문 및 모듈 상세 문서
│   ├── collectors.md        # 수집기 상세 명세서
│   └── pipeline.md          # 데이터 분석 파이프라인 명세서
├── snapshots/               # 수집된 JSON 스냅샷 저장소 (자동 생성)
│   ├── before/              # 변경/공격 전 스냅샷
│   └── after/               # 변경/공격 후 스냅샷
├── snapshot.py              # 메인 스냅샷 수집 스크립트 (병렬 수집 지원)
├── diff.py                  # before/after 스냅샷 차이점(Diff) 추출
├── normalize_diff.py        # Diff 데이터 정규화
├── diff_to_cypher.py        # Cypher 쿼리 변환
├── neo4j_loader.py          # Neo4j DB 적재 스크립트
├── requirements.txt         # 의존성 패키지 목록
└── README.md                # 프로젝트 안내 문서
```

---

## ⚙️ 설치 및 환경 설정 (Installation & Setup)

### 1. 사전 요구사항
- **Python 3.9+**
- **AWS CLI** 설정 및 Boto3 접근 권한 (IAM ReadOnlyAccess 권장)
- **Neo4j Database** (Neo4j Desktop, Docker, 또는 Neo4j AuraDB)

### 2. 의존성 패키지 설치
```bash
git clone https://github.com/In-suk-kang/cloud_temp.git
cd cloud_temp
pip install -r requirements.txt
```

---

## 🚀 사용 방법 (Usage Guide)

### Step 1. 인프라 스냅샷 수집 (`snapshot.py`)
변경 작업 또는 테스트 전후에 스냅샷을 각각 수집합니다.

```bash
# 변경 전(before) 스냅샷 수집
python snapshot.py before

# 인프라 변경 작업 또는 이벤트 발생 후...

# 변경 후(after) 스냅샷 수집
python snapshot.py after
```

### Step 2. 스냅샷 차이점(Diff) 추출 (`diff.py`)
`before` 및 `after` 스냅샷 간의 변동 사항을 추출합니다.

```bash
python diff.py
```

### Step 3. 데이터 정규화 및 Cypher 쿼리 변환 (`normalize_diff.py`, `diff_to_cypher.py`)
추출된 diff 데이터를 Graph DB 적재용 형식으로 처리합니다.

```bash
python normalize_diff.py
python diff_to_cypher.py
```

### Step 4. Neo4j DB 적재 (`neo4j_loader.py`)
변환된 Cypher 쿼리를 실행하여 Neo4j에 적재합니다.

```bash
python neo4j_loader.py
```

---


## 📄 참고 문서 (Documentation)

자세한 기능 설명 및 구성 명세는 `docs/` 디렉터리의 개별 문서를 참고하세요:
- [collectors.md](docs/collectors.md): 서비스별 수집 메타데이터 항목 및 예외 처리 구조
- [pipeline.md](docs/pipeline.md): 데이터 분석 파이프라인 및 Neo4j 연동 절차

---
*Developed for Cloud Security Audit & Log Deletion Forensic Research.*
