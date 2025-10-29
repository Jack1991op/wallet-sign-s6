@echo off
chcp 65001 >nul
echo ==================================================
echo     GitHub SSH 一键配置脚本
echo ==================================================
echo.

set "EMAIL=378228299@qq.com"
set "KEY_PATH=%USERPROFILE%\.ssh\id_ed25519"

if exist "%KEY_PATH%" (
    echo [1/5] 检测到已有密钥
) else (
    echo [1/5] 正在生成 SSH 密钥...
    ssh-keygen -t ed25519 -C "%EMAIL%" -f "%KEY_PATH%" -N "" >nul 2>&1
    echo [完成] 密钥生成成功
)

echo [2/5] 启动 ssh-agent...
start "" ssh-agent
timeout /t 1 >nul

echo [3/5] 添加私钥...
ssh-add "%KEY_PATH%" >nul 2>&1
echo [完成] 私钥已加载

echo [4/5] 复制公钥到剪贴板...
type "%KEY_PATH%.pub" | clip
echo [完成] 公钥已复制！去 GitHub 粘贴

start "" "https://github.com/settings/keys"

echo [5/5] 测试连接...
ssh -T git@github.com

echo.
echo 正在推送代码...
git remote set-url origin git@github.com:Jack1991op/wallet-sign-s6.git 2>nul
git push -u origin main

echo.
echo 全部完成！按任意键退出...
pause >nul
