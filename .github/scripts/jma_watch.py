"""
気象庁防災情報XML ポーリング → LINE WORKS Bot 通知スクリプト（GitHub Actions版）
四国4県（徳島・香川・愛媛・高知）の 洪水警報／高潮警報／土砂災害警戒情報／津波警報(大津波警報含む) を検知して通知する。

社内サーバー(192.168.2.184)側の常設監視が止まっても検知できるよう、
GitHub Actionsの定期実行(.github/workflows/jma_watch.yml)で並行運用する冗長系。
認証情報は一切ハードコードせず、すべてGitHub Actions Secretsの環境変数から読み込む。

処理の流れ:
    1. 気象庁の高頻度フィード(regular/extra/eqvol)を取得
    2. 新規の電文だけ中身を取得し、対象4県分の該当警報を抽出
    3. 直近 EXPIRY_HOURS 時間以内に同じ警報を通知済みならスキップ（重複防止）
    4. 該当あればLINE WORKS Botで通知
    5. 状態を jma_watch_state.json に保存（ワークフロー側でリポジトリにコミットして永続化する）
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import jwt
import requests

BASE_DIR = Path(__file__).parent

# ========== LINE WORKS 設定値（すべて環境変数必須。ハードコードした既定値は持たない） ==========
CLIENT_ID = os.environ["JMA_WATCH_CLIENT_ID"]
CLIENT_SECRET = os.environ["JMA_WATCH_CLIENT_SECRET"]
SERVICE_ACCOUNT_ID = os.environ["JMA_WATCH_SERVICE_ACCOUNT_ID"]
BOT_ID = os.environ["JMA_WATCH_BOT_ID"]
PRIVATE_KEY_PEM = os.environ["JMA_WATCH_PRIVATE_KEY_PEM"]
CHANNEL_ID = os.environ["JMA_WATCH_CHANNEL_ID"]
SOURCE_LABEL = os.environ.get("JMA_WATCH_SOURCE_LABEL", "GitHub")

HAZARD_MAP_URL = "https://pboonohara.github.io/Public/hazard_map_share.html"

# ========== 気象庁XML 設定値 ==========
FEED_URLS = [
    "https://www.data.jma.go.jp/developer/xml/feed/regular.xml",
    "https://www.data.jma.go.jp/developer/xml/feed/extra.xml",
    "https://www.data.jma.go.jp/developer/xml/feed/eqvol.xml",
]

# 対象4県: 気象庁市町村コードの先頭2桁
TARGET_PREF_CODE_PREFIX = {
    "36": "徳島県",
    "37": "香川県",
    "38": "愛媛県",
    "39": "高知県",
}

# 津波予報区コード(四国関連分)。愛媛県瀬戸内海側の別コードが存在する場合は要追加確認
TARGET_TSUNAMI_AREA_CODES = {
    "580": "徳島県",
    "590": "香川県",
    "600": "愛媛県（宇和海沿岸）",
    "610": "高知県",
}

# 同じ警報キーを再通知しないでおく期間(時間)。これを過ぎたら「再発表」扱いで再通知する
EXPIRY_HOURS = 6

NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "met": "http://xml.kishou.go.jp/jmaxml1/body/meteorology1/",
    "seis": "http://xml.kishou.go.jp/jmaxml1/body/seismology1/",
}

STATE_PATH = BASE_DIR / "jma_watch_state.json"


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"active": {}, "seen_entry_ids": []}


def save_state(state: dict) -> None:
    # seen_entry_idsは肥大化防止のため直近3000件だけ保持
    state["seen_entry_ids"] = state["seen_entry_ids"][-3000:]
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------- LINE WORKS ----------

def get_access_token() -> str:
    now = int(time.time())
    payload = {
        "iss": CLIENT_ID,
        "sub": SERVICE_ACCOUNT_ID,
        "iat": now,
        "exp": now + 60 * 60,
    }
    assertion = jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256")
    data = {
        "assertion": assertion,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "bot",
    }
    res = requests.post("https://auth.worksmobile.com/oauth2/v2.0/token", data=data, timeout=10)
    res.raise_for_status()
    return res.json()["access_token"]


def send_notification(access_token: str, text: str) -> None:
    url = f"https://www.worksapis.com/v1.0/bots/{BOT_ID}/channels/{CHANNEL_ID}/messages"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    body = {"content": {"type": "text", "text": text}}
    res = requests.post(url, headers=headers, json=body, timeout=10)
    res.raise_for_status()


# ---------- 気象庁XML取得 ----------

def fetch_feed_entries(feed_url: str) -> list[dict]:
    res = requests.get(feed_url, timeout=15)
    res.raise_for_status()
    root = ET.fromstring(res.content)
    entries = []
    for entry in root.findall("atom:entry", NS):
        entry_id = entry.findtext("atom:id", default="", namespaces=NS)
        link_el = entry.find("atom:link", NS)
        link = link_el.get("href") if link_el is not None else entry_id
        entries.append({"id": entry_id, "link": link})
    return entries


def detect_code(filename_url: str) -> str | None:
    for code in ("VPWW53", "VXWW50", "VTSE41"):
        if f"_{code}_" in filename_url:
            return code
    return None


# ---------- 電文ごとの判定 ----------

def check_weather_warning(xml_bytes: bytes) -> list[dict]:
    """気象特別警報・警報・注意報から 洪水警報／高潮警報（対象4県）を抽出"""
    root = ET.fromstring(xml_bytes)
    hits = []
    for warning in root.findall(".//met:Body/met:Warning", NS):
        if warning.get("type") != "気象警報・注意報（市町村等）":
            continue
        for item in warning.findall("met:Item", NS):
            kind_name = item.findtext("met:Kind/met:Name", default="", namespaces=NS)
            if kind_name not in ("洪水警報", "高潮警報"):
                continue
            status = item.findtext("met:Kind/met:Status", default="", namespaces=NS)
            if status != "発表":
                continue
            area_name = item.findtext("met:Area/met:Name", default="", namespaces=NS)
            area_code = item.findtext("met:Area/met:Code", default="", namespaces=NS)
            pref = TARGET_PREF_CODE_PREFIX.get(area_code[:2])
            if pref is None:
                continue
            hits.append({
                "key": f"weather_{area_code}_{kind_name}",
                "pref": pref,
                "area": area_name,
                "kind": kind_name,
            })
    return hits


def check_dosekisai(xml_bytes: bytes) -> list[dict]:
    """土砂災害警戒情報（対象4県）を抽出"""
    root = ET.fromstring(xml_bytes)
    hits = []
    for warning in root.findall(".//met:Body/met:Warning", NS):
        for item in warning.findall("met:Item", NS):
            status = item.findtext("met:Kind/met:Status", default="", namespaces=NS)
            if status != "発表":
                continue
            area_name = item.findtext("met:Area/met:Name", default="", namespaces=NS)
            area_code = item.findtext("met:Area/met:Code", default="", namespaces=NS)
            pref = TARGET_PREF_CODE_PREFIX.get(area_code[:2])
            if pref is None:
                continue
            hits.append({
                "key": f"dosha_{area_code}",
                "pref": pref,
                "area": area_name,
                "kind": "土砂災害警戒情報",
            })
    return hits


def check_tsunami(xml_bytes: bytes) -> list[dict]:
    """津波警報・大津波警報（対象4県沿岸）を抽出。津波注意報・津波予報は対象外"""
    root = ET.fromstring(xml_bytes)
    hits = []
    for item in root.findall(".//seis:Body/seis:Tsunami/seis:Forecast/seis:Item", NS):
        area_code = item.findtext("seis:Area/seis:Code", default="", namespaces=NS)
        if area_code not in TARGET_TSUNAMI_AREA_CODES:
            continue
        area_name = item.findtext("seis:Area/seis:Name", default="", namespaces=NS)
        kind_name = item.findtext("seis:Category/seis:Kind/seis:Name", default="", namespaces=NS)
        if "警報" not in kind_name or "注意報" in kind_name:
            continue
        hits.append({
            "key": f"tsunami_{area_code}",
            "pref": TARGET_TSUNAMI_AREA_CODES[area_code],
            "area": area_name,
            "kind": kind_name.replace("：発表", ""),
        })
    return hits


CHECKERS = {
    "VPWW53": check_weather_warning,
    "VXWW50": check_dosekisai,
    "VTSE41": check_tsunami,
}


def build_message(hit: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    return (
        f"【災害情報】{hit['pref']} {hit['area']}\n"
        f"{hit['kind']} が発表されました（確認時刻 {now}）\n"
        f"ハザードマップ・安否確認: {HAZARD_MAP_URL}\n"
        f"（名前入れて開始押して右上の赤ピンを押す）\n"
        f"（{SOURCE_LABEL}より）"
    )


def is_expired(last_seen_iso: str) -> bool:
    last_seen = datetime.fromisoformat(last_seen_iso)
    return (datetime.now(timezone.utc) - last_seen).total_seconds() > EXPIRY_HOURS * 3600


def main() -> None:
    state = load_state()
    seen = set(state["seen_entry_ids"])
    active = state["active"]
    new_hits = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for feed_url in FEED_URLS:
        try:
            entries = fetch_feed_entries(feed_url)
        except Exception as e:
            print(f"[WARN] フィード取得失敗: {feed_url}: {e}")
            continue

        for entry in entries:
            if entry["id"] in seen:
                continue
            seen.add(entry["id"])

            code = detect_code(entry["link"])
            if code is None:
                continue

            try:
                res = requests.get(entry["link"], timeout=15)
                res.raise_for_status()
                hits = CHECKERS[code](res.content)
            except Exception as e:
                print(f"[WARN] 電文取得/解析失敗: {entry['link']}: {e}")
                continue

            for hit in hits:
                record = active.get(hit["key"])
                if record is None or is_expired(record["last_seen"]):
                    new_hits.append(hit)
                active[hit["key"]] = {"last_seen": now_iso}

    if new_hits:
        access_token = get_access_token()
        for hit in new_hits:
            text = build_message(hit)
            try:
                send_notification(access_token, text)
                print(f"[SEND] {hit['key']}: {text}")
            except Exception as e:
                print(f"[ERROR] 送信失敗: {hit['key']}: {e}")
    else:
        print("[OK] 新規該当なし")

    state["seen_entry_ids"] = list(seen)
    state["active"] = active
    save_state(state)


if __name__ == "__main__":
    main()
