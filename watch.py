# -*- coding: utf-8 -*-
"""KINFA 강사공간 오픈교육 새 글 알림. 표준 라이브러리만 사용 (pip install 불필요)."""
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.parse
import urllib.request
from base64 import b64encode
from html import unescape

BASE = "https://edu.kinfa.or.kr"
LIST_URL = BASE + "/instr/info/instrInfoList.do?instrTabCd=2"
EMPTY = "접수중인 오픈 교육이 없습니다."
DENIED = "강사 회원만 접근 가능합니다."

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state.txt")
COOKIES = os.path.join(HERE, "cookies.txt")

# 세션 쿠키를 파일에 보관해 재사용한다. 매 실행마다 로그인하면 차단당함.
jar = http.cookiejar.MozillaCookieJar(COOKIES)
if os.path.exists(COOKIES):
    try:
        jar.load(ignore_discard=True)
    except Exception:
        pass
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [("User-Agent", "Mozilla/5.0"), ("Referer", BASE + "/")]


def load_cfg():
    """환경변수(GitHub Actions) 우선, 없으면 config.json(내 PC)."""
    if os.environ.get("KINFA_ID"):
        return {"id": os.environ["KINFA_ID"], "pw": os.environ["KINFA_PW"],
                "ntfy_topic": os.environ.get("NTFY_TOPIC", "")}
    return json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))


def fetch(url, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    with opener.open(url, body, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def pkcs1_pad(msg: bytes, k: int) -> bytes:
    """PKCS#1 v1.5 type-2 padding (jsbn rsa.js 의 pkcs1pad2 와 동일)."""
    if len(msg) > k - 11:
        raise ValueError("메시지가 키 길이보다 깁니다")
    ps = bytes(secrets.choice(range(1, 256)) for _ in range(k - len(msg) - 3))
    return b"\x00\x02" + ps + b"\x00" + msg


def rsa_encrypt(text: str, modulus_hex: str, exponent_hex: str) -> str:
    n, e = int(modulus_hex, 16), int(exponent_hex, 16)
    k = (n.bit_length() + 7) // 8
    c = pow(int.from_bytes(pkcs1_pad(text.encode("utf-8"), k), "big"), e, n)
    h = format(c, "x")
    return h if len(h) % 2 == 0 else "0" + h  # jsbn 과 동일하게 짝수 길이 hex


def login(cfg):
    page = fetch(BASE + "/login/login.do")
    mod = re.search(r'id="rsaPublicKeyModulus"\s+value="([0-9a-fA-F]+)"', page)
    exp = re.search(r'id="rsaPublicKeyExponent"\s+value="([0-9a-fA-F]+)"', page)
    if not (mod and exp):
        raise SystemExit("로그인 페이지 구조가 바뀌었습니다 (RSA 공개키를 못 찾음)")
    res = json.loads(fetch(BASE + "/login/loginExecAjax.do", {
        "mberId": cfg["id"],
        "mberPassword": rsa_encrypt(cfg["pw"], mod.group(1), exp.group(1)),
    }))
    if str(res.get("resultCode")) != "0":
        raise SystemExit("로그인 실패: %s" % res.get("resultMsg"))
    jar.save(ignore_discard=True)


def list_text(page: str) -> str:
    """목록 영역(검색 '찾기' 버튼 ~ footer)만 잘라 태그 제거한 텍스트."""
    region = page.split("찾기", 1)[-1].split("<footer", 1)[0]
    region = re.sub(r"(?is)<(script|style).*?</\1>", " ", region)
    return re.sub(r"\s+", " ", unescape(re.sub(r"(?s)<[^>]+>", " ", region))).strip()


def notify(cfg, title: str, body: str):
    topic = cfg.get("ntfy_topic")
    if topic:  # 휴대폰 알림 (ntfy 앱에서 같은 토픽 구독)
        enc = "=?UTF-8?B?%s?=" % b64encode(title.encode()).decode()
        req = urllib.request.Request(
            "https://ntfy.sh/" + topic, data=body.encode(),
            headers={"Title": enc, "Priority": "high", "Click": LIST_URL})
        urllib.request.urlopen(req, timeout=20).read()
    if os.name != "nt":  # GitHub Actions(리눅스)에서는 팝업 없음
        return
    # PC 팝업 (60초 뒤 자동 닫힘)
    msg = (body[:400] + "\n\n" + LIST_URL).replace("'", "''")
    try:
        subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
                          "(New-Object -ComObject Wscript.Shell).Popup('%s',60,'%s',64)"
                          % (msg, title.replace("'", "''"))])
    except OSError:
        pass


def main():
    cfg = load_cfg()
    page = fetch(LIST_URL)
    if DENIED in page:
        login(cfg)
        page = fetch(LIST_URL)
        if DENIED in page:
            raise SystemExit("로그인은 됐지만 강사 권한으로 접근이 안 됩니다")

    if EMPTY in page:
        if os.path.exists(STATE):
            open(STATE, "w", encoding="utf-8").write("")
        print("접수중인 오픈교육 없음")
        return

    text = list_text(page)
    digest = hashlib.sha256(text.encode()).hexdigest()
    old = open(STATE, encoding="utf-8").read() if os.path.exists(STATE) else ""
    if digest == old:
        print("변경 없음")
        return
    open(STATE, "w", encoding="utf-8").write(digest)
    notify(cfg, "오픈교육 새 글", text[:400])
    if os.environ.get("GITHUB_ACTIONS"):
        # 공개 저장소의 Actions 로그에 페이지 내용(강사명 등)을 남기지 않는다.
        print("알림 전송 (본문 %d자)" % len(text))
    else:
        print("알림 전송:", text[:120])


def test():
    k = 256
    block = pkcs1_pad(b"hello", k)
    assert len(block) == k and block[:2] == b"\x00\x02" and block[-6] == 0
    assert 0 not in block[2:-6] and block[-5:] == b"hello"
    assert pkcs1_pad(b"hello", k) != block  # 패딩은 매번 달라야 함
    n = "c7" + "f" * 126  # 512bit 짜리 임의의 홀수
    h = rsa_encrypt("pw", n, "10001")
    assert len(h) % 2 == 0 and int(h, 16) < int(n, 16)
    assert list_text("x찾기<div>가 나</div><footer>무시</footer>") == "가 나"
    print("self-check OK")


def ping():
    notify(load_cfg(), "알림 테스트", "이 메시지가 휴대폰에 뜨면 설정 완료입니다.")
    print("테스트 알림 전송")


if __name__ == "__main__":
    ({"--test": test, "--ping": ping}.get(sys.argv[1] if len(sys.argv) > 1 else "", main))()
