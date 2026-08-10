@echo off
cd /d "C:\Users\lmklo_v0vf840\OneDrive\Desktop\kinfa_watch_gh"
echo.
echo  Uploading to GitHub...
echo  A GitHub login window may appear - please approve it.
echo.
git push -u origin main
echo.
if errorlevel 1 (
  echo  [FAILED] Copy the message above and send it to Claude.
) else (
  echo  [DONE] Upload complete. Next: register the 3 Secrets on GitHub.
)
echo.
pause
