@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ============================================
echo   SAKURA Security Monitor インストーラー
echo ============================================
echo.

REM ===== インストール先 =====
set "INSTALL_DIR=%LOCALAPPDATA%\SAKURA-Security"
set "GITHUB_RAW=https://raw.githubusercontent.com/sakuranet-git/Google-Magika/main"

REM ===== Python チェック =====
echo [1/6] Python を確認中...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo     Python が見つかりません。インストールします...
    winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    if %errorlevel% neq 0 (
        echo.
        echo [ERROR] Python のインストールに失敗しました。
        echo         https://www.python.org から手動でインストールしてください。
        pause
        exit /b 1
    )
    REM PATH を更新
    set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"
    echo     Python インストール完了
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo     %%v 確認済み
)

REM ===== インストールフォルダ作成 =====
echo.
echo [2/6] インストールフォルダを作成中...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo     %INSTALL_DIR%

REM ===== 監視フォルダの設定 =====
echo.
echo [3/6] 監視フォルダを設定します
echo.
echo     監視したいフォルダのパスを入力してください。
echo     （Enterだけ押すと %USERPROFILE%\Documents になります）
echo.
set "DEFAULT_WATCH=%USERPROFILE%\Documents"
set /p "WATCH_DIR=  監視フォルダ: "
if "!WATCH_DIR!"=="" set "WATCH_DIR=%DEFAULT_WATCH%"

REM パスの末尾スラッシュを除去
if "!WATCH_DIR:~-1!"=="\" set "WATCH_DIR=!WATCH_DIR:~0,-1!"

echo     監視フォルダ: !WATCH_DIR!

REM config.json を書き出し
(
echo {
echo   "watch_dir": "!WATCH_DIR:\=\\!",
echo   "log_dir":   "!INSTALL_DIR:\=\\!"
echo }
) > "%INSTALL_DIR%\config.json"

REM ===== 最新ファイルをダウンロード =====
echo.
echo [4/6] 最新ファイルをダウンロード中...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest '%GITHUB_RAW%/security_monitor.py' -OutFile '%INSTALL_DIR%\security_monitor.py'}"
if %errorlevel% neq 0 (
    echo [ERROR] ダウンロードに失敗しました。インターネット接続を確認してください。
    pause
    exit /b 1
)
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest '%GITHUB_RAW%/requirements_security.txt' -OutFile '%INSTALL_DIR%\requirements_security.txt'}"
echo     ダウンロード完了

REM ===== ライブラリインストール =====
echo.
echo [5/6] 必要ライブラリをインストール中（少し時間がかかります）...
python -m pip install --quiet magika watchdog win11toast
if %errorlevel% neq 0 (
    echo [ERROR] ライブラリのインストールに失敗しました。
    pause
    exit /b 1
)
echo     インストール完了

REM ===== スタートアップ登録 =====
echo.
echo [6/6] 自動起動を設定中...

REM 起動用 bat をインストール先に作成
(
echo @echo off
echo start "" /min pythonw "%INSTALL_DIR%\security_monitor.py"
) > "%INSTALL_DIR%\start_monitor.bat"

REM スタートアップにショートカット登録
powershell -Command "& {$s=(New-Object -COM WScript.Shell).CreateShortcut([System.Environment]::GetFolderPath('Startup')+'\SAKURA Security Monitor.lnk'); $s.TargetPath='%INSTALL_DIR%\start_monitor.bat'; $s.WorkingDirectory='%INSTALL_DIR%'; $s.WindowStyle=7; $s.Save()}"
echo     スタートアップ登録完了

REM アンインストーラーを配置
(
echo @echo off
echo chcp 65001 ^>nul
echo echo SAKURA Security Monitor をアンインストールします...
echo taskkill /F /IM pythonw.exe /T ^>nul 2^>^&1
echo del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SAKURA Security Monitor.lnk" ^>nul 2^>^&1
echo rd /s /q "%INSTALL_DIR%" ^>nul 2^>^&1
echo echo アンインストール完了しました。
echo pause
) > "%INSTALL_DIR%\uninstall.bat"

REM ===== 起動 =====
echo.
echo ============================================
echo   インストール完了！
echo ============================================
echo.
echo   インストール先 : %INSTALL_DIR%
echo   監視フォルダ   : !WATCH_DIR!
echo   自動起動       : PC起動時に自動スタート
echo.
echo   今すぐ起動します...
echo.
start "" /min pythonw "%INSTALL_DIR%\security_monitor.py"
timeout /t 3 /nobreak >nul

tasklist /fi "IMAGENAME eq pythonw.exe" | find "pythonw.exe" >nul
if %errorlevel% == 0 (
    echo   起動成功！ Windows通知が届きます。
) else (
    echo   [WARN] 起動できませんでした。手動で start_monitor.bat を実行してください。
)
echo.
pause
