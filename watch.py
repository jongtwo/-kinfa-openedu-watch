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
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from html import unescape

BASE = "https://edu.kinfa.or.kr"
LIST_URL = BASE + "/instr/info/instrInfoList.do?instrTabCd=2"
EMPTY = "접수중인 오픈 교육이 없습니다."
DENIED = "강사 회원만 접근 가능합니다."

# 감시 시간대(KST). 글이 10시/2시에 올라오므로 10분 앞부터 켜서 cron 지연을 흡수한다.
WINDOWS = ((9 * 60 + 50, 10 * 60 + 30), (13 * 60 + 50, 14 * 60 + 30))
INTERVAL = 60  # 시간대 안에서의 확인 간격(초)

# 사이트가 잠깐 먹통일 때 실행 전체를 실패시키지 않기 위해 무시할 오류들.
NET_ERRORS = (urllib.error.URLError, TimeoutError, ConnectionError)

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state.txt")
COOKIES = os.path.join(HERE, "cookies.txt")
LAST_LOGIN = os.path.join(HERE, "lastlogin.txt")
PAUSE_UNTIL = os.path.join(HERE, "pause_until.txt")

# 사이트가 중복 로그인을 막으므로, 세션이 끊기면 내가 곧바로 다시 로그인하지 않는다.
# 사용자가 브라우저로 쓰는 중일 수 있어서, 이 시간만큼 물러나 있는다.
RELOGIN_WAIT = 1800

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
    open(LAST_LOGIN, "w").write(str(time.time()))


def read_time(path):
    try:
        return float(open(path).read().strip())
    except (OSError, ValueError):
        return 0.0


def paused() -> bool:
    """PAUSE.bat 로 걸어둔 일시중지가 아직 유효한가."""
    return time.time() < read_time(PAUSE_UNTIL)


def is_list_page(page: str) -> bool:
    """로그인 리다이렉트/오류 페이지를 목록으로 오인해 알림이 튀는 것을 막는다.
    검색 영역의 '찾기' 버튼은 진짜 목록 화면에만 있다."""
    return "찾기" in page


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
    if paused():
        print("일시중지 중 - 건너뜀 (%d분 남음)" % ((read_time(PAUSE_UNTIL) - time.time()) / 60))
        return
    page = fetch(LIST_URL)
    if DENIED in page or not is_list_page(page):
        # 방금 로그인했는데 벌써 세션이 끊겼다 = 사용자가 브라우저로 접속한 것.
        # 여기서 또 로그인하면 사용자가 튕기므로 물러난다.
        waited = time.time() - read_time(LAST_LOGIN)
        if waited < RELOGIN_WAIT:
            print("세션이 끊김 - 사용자가 사이트 사용 중으로 보여 %d분 뒤 재시도"
                  % ((RELOGIN_WAIT - waited) / 60))
            return
        login(cfg)
        page = fetch(LIST_URL)
        if DENIED in page:
            raise SystemExit("로그인은 됐지만 강사 권한으로 접근이 안 됩니다")
    if not is_list_page(page):
        # 목록이 아닌 화면을 '변경'으로 오인하면 알림이 계속 튄다. 조용히 넘긴다.
        print("목록 화면을 못 받음 - 이번 확인은 건너뜀")
        return

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
    assert read_time(os.path.join(HERE, "없는파일.txt")) == 0.0  # 없으면 0, 예외 아님
    assert is_list_page("<div>찾기</div>")  # 진짜 목록 화면
    assert not is_list_page("<noscript>자바스크립트를 지원하지 않는</noscript>")  # 리다이렉트 화면
    assert in_window(10 * 60) and in_window(14 * 60)  # 10시, 2시 정각
    assert in_window(9 * 60 + 50) and in_window(13 * 60 + 50)  # 10분 앞부터 켜짐
    assert in_window(10 * 60 + 29) and in_window(14 * 60 + 29)
    assert not in_window(9 * 60 + 49) and not in_window(10 * 60 + 30)  # 경계
    assert not in_window(12 * 60) and not in_window(14 * 60 + 30)  # 사이 시간엔 꺼짐
    assert kst_minutes(0) == 9 * 60  # UTC 0시 = KST 9시
    print("self-check OK")


def kst_minutes(now=None):
    t = time.gmtime((time.time() if now is None else now) + 9 * 3600)  # 러너는 UTC
    return t.tm_hour * 60 + t.tm_min


def in_window(minutes):
    return any(a <= minutes < b for a, b in WINDOWS)


def ping():
    notify(load_cfg(), "알림 테스트", "이 메시지가 휴대폰에 뜨면 설정 완료입니다.")
    print("테스트 알림 전송")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--test":
        test()
    elif arg == "--ping":
        ping()
    elif os.environ.get("GITHUB_ACTIONS") and in_window(kst_minutes()):
        # GitHub 은 cron 트리거를 40~60분까지 지연시킨다. 그래서 시간대가 시작되면
        # 이 실행 하나가 끝까지 살아 있으면서 INTERVAL 마다 확인한다 (세션 재사용).
        fails, told = 0, False
        while in_window(kst_minutes()):
            try:
                main()
                fails = 0
            except NET_ERRORS + (SystemExit,) as e:
                # 여기서 중단하면 남은 시간대를 통째로 놓친다. 계속 돌되,
                # 3회 연속이면 원인을 폰으로 한 번만 알려준다.
                fails += 1
                print("확인 실패(%d회 연속): %s" % (fails, e))
                if fails >= 3 and not told:
                    told = True
                    try:
                        notify(load_cfg(), "감시 오류", str(e))
                    except Exception:
                        pass
            time.sleep(INTERVAL)
    else:
        try:
            main()
        except NET_ERRORS + (SystemExit,) as e:
            # 실패로 끝내면 GitHub 이 경고 메일을 보낸다. 다음 실행에서 어차피 재시도한다.
            print("이번 확인 실패 - 넘어감:", e)
