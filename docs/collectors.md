# AWS Security Snapshot Tool - Collectors 문서화 (`collectors-v2.md`)

`collectors` 모듈은 AWS 인프라의 주요 보안 설정 및 리소스 메타데이터를 Boto3 SDK를 활용하여 수집하는 핵심 수집기 세트입니다 [3, 4]. 수집된 데이터는 JSON 스냅샷 형태(`snapshots/before/`, `snapshots/after/`)로 저장되며, 변경 사항 비교(`diff.py`) 및 Neo4j 그래프 DB 적재 파이프라인으로 전달됩니다 [3, 5].

---

## 1. 공통 아키텍처 및 최적화 (Architecture & Optimization)

* **병렬 실행 파이프라인**: 메인 스크립트인 `snapshot.py` (`snapshot-v2.py`)가 `ThreadPoolExecutor`를 활용하여 각 수집기(collector) 모듈을 동시 병렬로 호출함으로써 수집 시간을 대폭 단축했습니다 [3, 5].
* **동적 리졸버 및 예외 처리**: `resolve_collector_func`를 통해 서비스별 수집 함수 이름을 유연하게 자동 탐색하며, API 호출 시 권한 부족(`ClientError`) 등의 에러 발생 시 `safe_call`을 통해 수집 프로세스 전체가 중단되지 않도록 안전하게 핸들링합니다 [4].
* **모듈화 구조**: 각 AWS 서비스별로 독립된 수집 로직을 수행하여 확장성과 유지보수성을 높였습니다 [4].

---

## 2. 서비스별 Collector 상세 명세 (Collector Specifications)

### 2.1 IAM Collector (`iam.json`)
AWS 계정 내 접근 제어 및 권한 체계를 수집합니다 [4].
* **Users**: IAM 사용자 목록 및 연결된 정책
* **Groups**: IAM 그룹 목록 및 멤버십/정책
* **Roles**: IAM 역할 목록, 신뢰 관계(Trust Relationship) 및 역할 정책
* **Policies**: 연결된(Attached) 및 인라인(Inline) 정책 상세 정보

### 2.2 Security Group Collector (`security_group.json`)
네트워크 경계 보안 규칙을 수집합니다 [4].
* **Inbound Rules**: 인바운드 허용 트래픽 (프로토콜, 포트 범위, 소스 CIDR/보안그룹)
* **Outbound Rules**: 아웃바운드 허용 트래픽 (프로토콜, 포트 범위, 목적지 CIDR/보안그룹)

### 2.3 EC2 Collector (`ec2.json`)
컴퓨팅 리소스 및 연결된 네트워크/스토리지 메타데이터를 수집합니다 [4].
* **Instances**: EC2 인스턴스 상태(Running/Stopped 등), 유형, VPC/Subnet 배치
* **Network Interfaces (ENI)**: ENI 바인딩 상태, IP 주소 및 보안그룹 연결 정보
* **Volumes (EBS)**: EBS 볼륨 상태 및 암호화 설정 여부
* **Tags**: 리소스 식별용 태그 정보

### 2.4 S3 Collector (`s3.json`)
스토리지 객체 보안 및 접근 통제 설정을 수집합니다 [4].
* **Bucket Region**: S3 버킷 배치 리전
* **Public Access Block**: 퍼블릭 액세스 차단(Public Access Block) 설정 상태
* **Bucket Policy**: S3 버킷 정책(JSON)
* **ACL**: 버킷 ACL 및 접근 권한
* **Encryption**: 기본 서버 측 암호화(SSE-S3 / SSE-KMS) 설정 상태

### 2.5 VPC Collector (`vpc.json`)
가상 네트워크 구조 및 토폴로지 정보를 수집합니다 [4].
* **VPC & Subnets**: VPC 대역 및 서브넷 CIDR, 가용 영역
* **Route Tables**: 라우트 테이블 규칙 및 대상 게이트웨이
* **Internet Gateways**: 인터넷 게이트웨이(IGW) 바인딩 상태
* **Network ACLs (NACL)**: 서브넷 수준 네트워크 접근 제어 규칙

### 2.6 CloudTrail Collector (`cloudtrail.json`)
감사 및 침해 사고 추적 로깅 설정 상태를 수집합니다 [4].
* **Trail Logging Status**: CloudTrail 추적 활성화 여부 (`is_logging`)
* **Event Selectors**: 수집 중인 관리 이벤트 및 데이터 이벤트 설정 범위

---

## 3. 권장 고도화 사항 (Advanced Enhancements)

1. **Boto3 Paginator 적용**: 대규모 인프라 환경에서 1회 API 제한(예: 100~1,000개)으로 인한 리소스 누락을 방지하기 위해 `get_paginator()` 기반 자동 페이징 처리를 보강합니다.
2. **Multi-Region 수집 확장**: `describe_regions()`로 활성화된 전체 AWS 리전을 순회 수집하여 글로벌 인프라 스냅샷을 생성합니다.
3. **CloudWatch Logs & S3 Object Lock 수집 추가**: 로그 삭제 및 은닉 행위 추적의 완성도를 높이기 위해 CloudWatch Logs 보관 주기 및 S3 Object Lock/버전 관리 상태 수집을 확장합니다.

---

## 4. 출력 데이터 구조 (Output Structure)

수집된 데이터는 `snapshot.py` 실행 시 지정한 인자(`before` 또는 `after`) 및 `--output-dir` 설정에 따라 디렉토리 구조로 JSON 저장됩니다 [4, 5]:

```
snapshots/
├── before/
│   ├── iam.json
│   ├── security_group.json
│   ├── ec2.json
│   ├── s3.json
│   ├── vpc.json
│   └── cloudtrail.json
└── after/
    └── ...
```

