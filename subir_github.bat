@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
where git >nul 2>nul || (echo [X] Instala Git: https://git-scm.com/download/win & pause & exit /b 1)
if not exist .git git init >nul
git config user.name >nul 2>nul || (set /p N=Tu nombre para Git: & git config user.name "!N!")
git config user.email >nul 2>nul || (set /p E=Tu correo de GitHub: & git config user.email "!E!")
git add -A
git diff --cached --quiet || git commit -m "Actualizacion %date% %time%"
git branch -M main
git remote get-url origin >nul 2>nul
if errorlevel 1 (
  where gh >nul 2>nul
  if not errorlevel 1 (
    gh auth status >nul 2>nul || gh auth login
    gh repo create voto-seguro-comunitario --public --source . --remote origin --push && goto ok
  )
  set /p URL=Pega la URL de tu repositorio vacio ^(https://github.com/USUARIO/REPO.git^): 
  git remote add origin !URL!
)
git push -u origin main && goto ok
echo [X] Fallo el push. Revisa tu sesion de GitHub o la URL del repositorio.
pause & exit /b 1
:ok
echo.
echo Listo: codigo subido a GitHub.
pause
