"""의존성(SCA, Software Composition Analysis) 스캐너 — requirements.txt(pip)/package.json(npm)에서
패키지@버전을 추출해 App 15의 NVD 연동(cve_lookup_service)으로 알려진 취약점을 best-effort로 찾는다.

⚠️ 정확한 CPE 기반 매칭이 아니라 NVD 키워드 검색이다 — 이름이 흔한 패키지는 무관한 CVE가 섞일 수 있고,
버전 범위(>=, ^ 등)는 정확히 매칭되지 않는다. 정밀한 SCA가 필요하면 pip-audit/npm audit/OWASP
Dependency-Check/Trivy 같은 전용 도구를 권장한다는 점을 UI에도 명시한다.

NVD 무료 레이트리밋(키 없으면 30초당 5건)을 넘지 않도록 패키지 수를 제한하고 호출 사이에 delay를 둔다.
"""

import asyncio
import json
import re
from services import cve_lookup_service

MAX_PACKAGES = 8

_PIP_LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.\-]*)")


def parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PIP_LINE_RE.match(line)
        if not m:
            continue
        name, op, version = m.groups()
        packages.append({"name": name, "version": version or None, "pinned": op == "==" and bool(version)})
    return packages


def parse_package_json(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    packages = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            version = re.sub(r"^[\^~>=<\s]+", "", spec).strip()
            packages.append({"name": name, "version": version or None, "pinned": bool(re.match(r"^\d", spec.strip()))})
    return packages


def _highest_severity(results: list[dict]) -> str | None:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best = None
    for entry in results:
        for cve in entry.get("matched_cves", []):
            sev = (cve.get("cvss") or {}).get("base_severity")
            if sev and (best is None or order.get(sev, 0) > order.get(best, 0)):
                best = sev
    return best


async def scan_dependencies(manifest_type: str, content: str) -> dict:
    packages = parse_package_json(content) if manifest_type == "npm" else parse_requirements_txt(content)
    if not packages:
        return {"error": "parse_failed", "message": "패키지를 파싱하지 못했습니다. 형식을 확인하세요 (pip: name==1.2.3, npm: package.json의 dependencies)."}

    seen: dict[str, dict] = {}
    for p in packages:
        existing = seen.get(p["name"])
        if existing is None or (p["pinned"] and not existing["pinned"]):
            seen[p["name"]] = p
    unique = sorted(seen.values(), key=lambda p: not p["pinned"])
    truncated = len(unique) > MAX_PACKAGES
    to_scan = unique[:MAX_PACKAGES]

    delay = 0.7 if cve_lookup_service.HAS_API_KEY else 6.5
    results = []
    for i, pkg in enumerate(to_scan):
        entry = {"name": pkg["name"], "version": pkg["version"], "pinned": pkg["pinned"], "matched_cves": [], "note": None}
        if not pkg["version"]:
            entry["note"] = "버전이 명시되지 않아 검색을 건너뛰었습니다."
        else:
            res = await cve_lookup_service.search_cves(f"{pkg['name']} {pkg['version']}")
            if "error" in res:
                entry["note"] = res.get("message")
            else:
                raw = res.get("results", [])
                name_lower = pkg["name"].lower()
                filtered = [r for r in raw if name_lower in (r.get("description") or "").lower()]
                entry["matched_cves"] = filtered
                if raw and not filtered:
                    entry["note"] = f"NVD 키워드 검색 결과가 있었지만 설명에 '{pkg['name']}'이(가) 포함되지 않아 무관한 매칭으로 판단해 제외했습니다."
                elif not pkg["pinned"]:
                    entry["note"] = "버전 범위 지정이라 정확한 매칭이 아닐 수 있습니다."
        results.append(entry)
        if i < len(to_scan) - 1:
            await asyncio.sleep(delay)

    return {
        "manifest_type": manifest_type,
        "total_packages_found": len(unique),
        "packages_scanned": len(to_scan),
        "truncated": truncated,
        "results": results,
        "highest_severity": _highest_severity(results),
    }


def generate_markdown_report(entry: dict) -> str:
    lines = [
        "# 의존성(SCA) 취약점 스캔 리포트",
        "",
        f"**매니페스트 유형:** {'npm (package.json)' if entry.get('manifest_type') == 'npm' else 'pip (requirements.txt)'}  ",
        f"**발견된 패키지:** {entry.get('total_packages_found', 0)}개 (스캔: {entry.get('packages_scanned', 0)}개)  ",
        "",
        "> NVD 키워드 검색 기반 best-effort 매칭입니다. 정밀한 SCA는 pip-audit/npm audit/Trivy 등 전용 도구를 사용하세요.",
        "",
        "---",
        "",
    ]
    for r in entry.get("results", []):
        lines.append(f"## {r['name']}" + (f" ({r['version']})" if r.get("version") else ""))
        lines.append("")
        if r.get("note"):
            lines.append(f"> {r['note']}")
            lines.append("")
        if r.get("matched_cves"):
            for cve in r["matched_cves"]:
                cvss = cve.get("cvss") or {}
                lines.append(f"- **{cve.get('id')}** [{cvss.get('base_severity', 'N/A')} {cvss.get('base_score', '')}] {cve.get('description', '')[:150]}")
        else:
            lines.append("- 일치하는 CVE 없음")
        lines.append("")
    return "\n".join(lines)
