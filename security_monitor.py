#!/usr/bin/env python3
"""
SAKURA Security Monitor v1.3.0
Development ディレクトリの常駐監視 + Downloads ダウンロード即時スキャン + 自動アップデート
"""

import os
import sys
import time
import logging
import shutil
import subprocess
import urllib.request
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from magika import Magika
from win11toast import notify as win11_notify

# ===== 設定 =====
APP_NAME  = "SAKURA Security Monitor"
VERSION   = "1.3.0"

# スクリプトと同じフォルダの config.json を読み込む
_BASE_DIR = Path(__file__).resolve().parent
_CONFIG_FILE = _BASE_DIR / "config.json"

def _load_config() -> dict:
    """config.json からパス設定を読み込む。なければデフォルト値を使用。"""
    defaults = {
        "watch_dir": str(Path.home() / "Documents"),
        "log_dir":   str(_BASE_DIR),
    }
    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE, encoding='utf-8') as f:
                data = json.load(f)
            defaults.update(data)
        except Exception:
            pass
    return defaults

_cfg     = _load_config()
WATCH_DEV = Path(_cfg["watch_dir"])
WATCH_DL  = Path.home() / "Downloads"
LOG_FILE  = Path(_cfg["log_dir"]) / "security_report.txt"

# スキップするディレクトリ名
EXCLUDE_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', '.next',
    'backups', 'trash', 'flipbooks', 'gemini', 'manus', 'tmp',
    '_internal',        # Python 実行ファイルの内部ライブラリ
    'dist-info',        # pip パッケージメタ情報
    'site-packages',    # Python パッケージ
}

# ダウンロード中の一時拡張子（スキャン対象外）
TEMP_EXTENSIONS = {'.tmp', '.crdownload', '.part', '.download', '.partial'}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# ─────────────────────────────────────────────────────────
# 【危険な偽装の定義】
# 「画像・ドキュメント・アーカイブ」拡張子なのに
# 「実行ファイル・スクリプト」が入っている場合のみアラート
# ─────────────────────────────────────────────────────────

# 非実行系の拡張子（これらに実行系が入っていたら危険）
SAFE_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico', '.svg',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.mp4', '.mp3', '.wav', '.avi', '.mov',
}

# 本当に危険な Magika ラベル（実行ファイル・サーバーサイドスクリプト）
DANGEROUS_LABELS = {
    'pe',           # Windows 実行ファイル (.exe/.dll)
    'elf',          # Linux 実行ファイル
    'dex',          # Android 実行ファイル
    'msi',          # Windows インストーラ
    'apk',          # Android パッケージ
    'php',          # PHP スクリプト
    'asp',          # ASP スクリプト
    'jsp',          # Java Server Pages
    'shell',        # シェルスクリプト
    'powershell',   # PowerShell スクリプト
    'vba',          # VBA マクロ
}


# ===== ロガー =====
def _setup_logger() -> logging.Logger:
    lg = logging.getLogger('sakura_security')
    lg.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
    fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    lg.addHandler(fh)
    lg.addHandler(ch)
    return lg

logger = _setup_logger()


# ===== 通知 (win11toast) =====
def notify(title: str, message: str):
    try:
        win11_notify(title, message)
    except Exception as e:
        logger.debug(f"通知送信失敗: {e}")


# ===== ユーティリティ =====
def should_skip(path: Path) -> bool:
    if path == LOG_FILE:
        return True
    if path.name.startswith('.'):
        return True
    if path.suffix.lower() in TEMP_EXTENSIONS:
        return True
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
        # dist-info ディレクトリ（例: numpy-2.1.dist-info）
        if part.endswith('.dist-info') or part.endswith('.data'):
            return True
    return False


def scan_file(path: Path, magika: Magika) -> dict:
    """Magika API でファイルをスキャン。本当に危険なものだけ検出。"""
    result = {
        'label': None,
        'mime_type': None,
        'score': 0.0,
        'is_dangerous': False,
        'message': '',
    }
    try:
        if not path.exists() or not path.is_file():
            return result
        size = path.stat().st_size
        if size == 0 or size > MAX_FILE_SIZE:
            return result

        # ─── Magika API 問い合わせ ───
        res = magika.identify_path(path)
        out = res.output
        result['label']     = out.label
        result['mime_type'] = out.mime_type
        result['score']     = getattr(res, 'score', 1.0)

        ext   = path.suffix.lower()
        label = out.label

        # 危険判定：「安全な拡張子」なのに「危険なラベル」が検出された場合のみ
        if ext in SAFE_EXTENSIONS and label in DANGEROUS_LABELS:
            result['is_dangerous'] = True
            result['message'] = (
                f'危険な偽装を検出: "{ext}" の中身が {label} ({out.mime_type})'
            )

    except PermissionError:
        pass
    except Exception as e:
        logger.debug(f"スキャンエラー {path}: {e}")

    return result


def _score_str(score: float) -> str:
    return f'{score * 100:.0f}%' if score else ''


# ===== Development 監視ハンドラ =====
class DevelopmentHandler(FileSystemEventHandler):

    def __init__(self, magika: Magika):
        self.magika = magika
        self._cache: dict[str, float] = {}

    def _debounce(self, key: str, interval: float = 2.0) -> bool:
        now = time.time()
        if now - self._cache.get(key, 0) < interval:
            return True
        self._cache[key] = now
        return False

    def on_created(self, event):
        path = Path(event.src_path)
        if should_skip(path) or self._debounce(str(path)):
            return
        if event.is_directory:
            logger.info(f'[追加] ディレクトリ: {path.name}')
            notify('📁 ディレクトリ追加', path.name)
        else:
            self._scan_notify(path, 'created')

    def on_modified(self, event):
        path = Path(event.src_path)
        if should_skip(path) or event.is_directory or self._debounce(str(path), 3.0):
            return
        self._scan_notify(path, 'modified')

    def on_deleted(self, event):
        path = Path(event.src_path)
        if should_skip(path) or self._debounce(str(path)):
            return
        if event.is_directory:
            logger.warning(f'[削除] ディレクトリ: {path.name}')
            notify('🗑️ ディレクトリ削除', path.name)
        else:
            logger.warning(f'[削除] ファイル: {path.name}')
            notify('🗑️ ファイル削除', path.name)

    def on_moved(self, event):
        src = Path(event.src_path)
        dst = Path(event.dest_path)
        if should_skip(src) or self._debounce(str(src)):
            return
        kind = 'ディレクトリ' if event.is_directory else 'ファイル'
        logger.info(f'[移動] {kind}: {src.name} → {dst.name}')
        if not event.is_directory and dst.exists():
            self._scan_notify(dst, 'moved')

    def _scan_notify(self, path: Path, event_type: str):
        if not path.exists() or not path.is_file():
            return
        r = scan_file(path, self.magika)
        label = r['label'] or 'unknown'
        score = _score_str(r['score'])

        if r['is_dangerous']:
            logger.error(f'[DANGER] {r["message"]} — {path}')
            notify('🚨 危険なファイルを検出！', f'{path.name}\n{r["message"]}')
        elif event_type == 'created':
            logger.info(f'[追加] {path.name} → {label} {score}')
            notify('📄 ファイル追加', f'{path.name}\n種別: {label}  信頼度: {score}')
        elif event_type == 'modified':
            logger.info(f'[変更] {path.name} → {label}')


# ===== Downloads 監視ハンドラ =====
class DownloadsHandler(FileSystemEventHandler):
    """ダウンロード完了を検知し Magika API でクイック分析"""

    def __init__(self, magika: Magika):
        self.magika = magika
        self._scanned: set[str] = set()

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if should_skip(path):
            return
        time.sleep(2.0)
        self._quick_scan(path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if should_skip(path) or str(path) in self._scanned:
            return
        try:
            s1 = path.stat().st_size
            time.sleep(1.5)
            s2 = path.stat().st_size
            if s1 == s2 and s2 > 0:
                self._quick_scan(path)
        except Exception:
            pass

    def _quick_scan(self, path: Path):
        """Magika API クイック分析 → Windows 通知"""
        if not path.exists() or not path.is_file():
            return
        key = str(path)
        if key in self._scanned:
            return
        self._scanned.add(key)

        r = scan_file(path, self.magika)
        label = r['label'] or 'unknown'
        mime  = r['mime_type'] or ''
        score = _score_str(r['score'])

        if r['is_dangerous']:
            logger.error(f'[DL DANGER] {r["message"]} — {path.name}')
            notify('🚨 危険なファイルをダウンロード！',
                   f'{path.name}\n{r["message"]}')
        else:
            logger.info(f'[DL] {path.name} → {label} ({mime}) {score}')
            notify('📥 ダウンロード分析完了',
                   f'{path.name}\n種別: {label}\n{mime}\n信頼度: {score}')


# ===== 自動アップデート =====
UPDATE_VERSION_URL = "https://raw.githubusercontent.com/sakuranet-git/Google-Magika/master/version.json"
UPDATE_SCRIPT_URL  = "https://raw.githubusercontent.com/sakuranet-git/Google-Magika/master/security_monitor.py"
SCRIPT_PATH = Path(__file__).resolve()


def _ver_tuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split('.'))
    except Exception:
        return (0, 0, 0)


def check_and_update():
    """GitHub の version.json を確認し、新バージョンがあれば自動更新・再起動"""
    try:
        with urllib.request.urlopen(UPDATE_VERSION_URL, timeout=5) as resp:
            data = json.loads(resp.read())
        latest = data.get('version', '0.0.0')

        if _ver_tuple(latest) <= _ver_tuple(VERSION):
            logger.info(f'バージョン確認済み — 最新です (v{VERSION})')
            return

        logger.info(f'新バージョン v{latest} を検出。ダウンロード中...')
        notify('🔄 アップデート中', f'v{VERSION} → v{latest}')

        # バックアップ作成
        backup = SCRIPT_PATH.with_suffix('.py.bak')
        shutil.copy2(SCRIPT_PATH, backup)

        # 新しいスクリプトをダウンロード
        with urllib.request.urlopen(UPDATE_SCRIPT_URL, timeout=30) as resp:
            SCRIPT_PATH.write_bytes(resp.read())

        logger.info(f'アップデート完了 (v{latest})。再起動します...')
        notify('✅ アップデート完了', f'v{latest} で再起動します')

        # 再起動
        subprocess.Popen([sys.executable, str(SCRIPT_PATH)])
        sys.exit(0)

    except Exception as e:
        logger.debug(f'アップデートチェック失敗（オフライン？）: {e}')


# ===== 起動時スキャン =====
def initial_scan(magika: Magika):
    logger.info('=' * 60)
    logger.info(f'{APP_NAME} v{VERSION}')
    logger.info(f'監視: {WATCH_DEV}')
    logger.info(f'監視: {WATCH_DL} (Downloads)')
    logger.info('初回スキャン中...')

    danger_count = scan_count = 0
    for root, dirs, files in os.walk(WATCH_DEV):
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDE_DIRS
            and not d.startswith('.')
            and not d.endswith('.dist-info')
            and not d.endswith('.data')
        ]
        for name in files:
            p = Path(root) / name
            if should_skip(p):
                continue
            scan_count += 1
            r = scan_file(p, magika)
            if r['is_dangerous']:
                danger_count += 1
                logger.error(f'[SCAN DANGER] {r["message"]} — {p}')

    logger.info(f'初回スキャン完了: {scan_count} ファイル / 危険: {danger_count} 件')
    if danger_count:
        notify('⚠️ スキャン完了', f'{danger_count} 件の危険なファイルを検出しました')
    else:
        notify('✅ スキャン完了', f'{scan_count} ファイルをスキャン — 問題なし')
    logger.info('リアルタイム監視を開始しました')
    logger.info('=' * 60)


# ===== エントリポイント =====
def main():
    magika = Magika()
    check_and_update()   # 起動時に自動アップデート確認
    initial_scan(magika)

    observer = Observer()
    observer.schedule(DevelopmentHandler(magika), str(WATCH_DEV), recursive=True)
    observer.schedule(DownloadsHandler(magika),   str(WATCH_DL),  recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('停止します...')
        observer.stop()

    observer.join()
    logger.info(f'{APP_NAME} 終了')


if __name__ == '__main__':
    main()
