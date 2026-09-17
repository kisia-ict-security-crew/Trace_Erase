#!/usr/bin/env python3
"""
AWS Security Snapshot Tool - Main Execution Pipeline (Refactored with Parallel Execution)

주요 개선 사항:
1. 상단에 표준 임포트 구문 일재 배치 (collectors 모듈 포함)
2. ThreadPoolExecutor를 이용한 6대 AWS 서비스 수집기 병렬(Multi-threading) 실행
3. argparse 기반 스냅샷 타입(before/after) 및 옵션 파라미터 제어
4. logging 모듈 기반 타임스탬프 및 수집 소요 시간 측정
5. 예외 발생 시 개별 수집 실패가 전체 프로세스에 영향을 주지 않는 안전한 핸들링
"""

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Collectors 패키지 모듈 표준 상단 임포트
from collectors.iam import collect_iam
from collectors.sg import collect_security_group
from collectors.ec2 import collect_ec2
from collectors.s3 import collect_s3
from collectors.vpc import collect_vpc
from collectors.ct import collect_cloudtrail

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AWS_Snapshot")

# 수집기 매핑 사전 정의
COLLECTORS = {
    "iam": collect_iam,
    "security_group": collect_security_group,
    "ec2": collect_ec2,
    "s3": collect_s3,
    "vpc": collect_vpc,
    "cloudtrail": collect_cloudtrail,
}


def run_single_collector(service_name, collect_func, output_dir):
    """
    단일 수집기 스레드 실행 함수
    """
    start_time = time.time()
    logger.info(f"[{service_name.upper()}] 수집 시작...")
    
    try:
        data = collect_func()
        elapsed = time.time() - start_time
        
        # 파일 저장
        output_file = output_dir / f"{service_name}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
        logger.info(f"[{service_name.upper()}] 수집 완료! ({elapsed:.2f}초 소요) -> {output_file}")
        return service_name, True, elapsed, None
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[{service_name.upper()}] 수집 중 오류 발생: {e} ({elapsed:.2f}초 소요)")
        return service_name, False, elapsed, str(e)


def main():
    parser = argparse.ArgumentParser(
        description="AWS Infrastructure Security Snapshot Tool (Parallel Collector)"
    )
    parser.add_argument(
        "snapshot_type",
        nargs="?",
        default="before",
        choices=["before", "after"],
        help="스냅샷 종류 (before 또는 after, 기본값: before)",
    )
    parser.add_argument(
        "--type",
        dest="type_flag",
        choices=["before", "after"],
        help="스냅샷 종류 플래그 (옵션)",
    )
    parser.add_argument(
        "--output-dir",
        default="snapshots",
        help="스냅샷 저장 기본 디렉터리 (기본값: snapshots)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=6,
        help="병렬 실행 스레드 수 (기본값: 6)",
    )

    args = parser.parse_args()
    
    # snapshot_type 결정
    snapshot_type = args.type_flag if args.type_flag else args.snapshot_type
    
    # 출력 디렉터리 생성
    target_dir = Path(args.output_dir) / snapshot_type
    target_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 60)
    logger.info(f"AWS 보안 스냅샷 수집 시작 [타입: {snapshot_type.upper()}]")
    logger.info(f"저장 경로: {target_dir.resolve()}")
    logger.info("=" * 60)

    total_start_time = time.time()
    results = {}

    # ThreadPoolExecutor를 사용한 병렬 수집 실행
    with ThreadPoolExecutor(max_workers=min(args.max_workers, len(COLLECTORS))) as executor:
        future_to_service = {
            executor.submit(run_single_collector, name, func, target_dir): name
            for name, func in COLLECTORS.items()
        }

        for future in as_completed(future_to_service):
            service_name = future_to_service[future]
            try:
                srv_name, success, elapsed, err = future.result()
                results[srv_name] = {"success": success, "time": elapsed, "error": err}
            except Exception as exc:
                logger.error(f"[{service_name.upper()}] 스레드 처리 중 예외 발생: {exc}")
                results[service_name] = {"success": False, "time": 0, "error": str(exc)}

    total_elapsed = time.time() - total_start_time

    # 요약 출력
    logger.info("=" * 60)
    logger.info(f"스냅샷 수집 완료! (총 소요 시간: {total_elapsed:.2f}초)")
    logger.info("수집 결과 요약:")
    for service, res in results.items():
        status = "SUCCESS" if res["success"] else f"FAILED ({res['error']})"
        logger.info(f" - {service.upper():<15}: {status} ({res['time']:.2f}초)")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()