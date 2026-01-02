@echo off
REM ============================================================================
REM Script de compilation - FULL_extraction_LB5 v1.1
REM Compile le script Python en .exe standalone avec PyInstaller
REM ============================================================================

echo.
echo ========================================================================
echo    COMPILATION FULL_extraction_LB5 v1.1
echo ========================================================================
echo.

REM Vérifier si Python est installé
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Python n'est pas installé ou pas dans le PATH
    echo.
    echo Installez Python depuis : https://www.python.org/downloads/
    echo Cochez "Add Python to PATH" pendant l'installation
    pause
    exit /b 1
)

echo [OK] Python detecte
echo.

REM Vérifier si PyInstaller est installé
pip show pyinstaller >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] PyInstaller n'est pas installe
    echo [INFO] Installation de PyInstaller...
    pip install pyinstaller
    if %ERRORLEVEL% NEQ 0 (
        echo [ERREUR] Echec installation PyInstaller
        pause
        exit /b 1
    )
)

echo [OK] PyInstaller detecte
echo.

REM Installer les dépendances
echo [INFO] Installation des dependances...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Echec installation dependances
    pause
    exit /b 1
)

echo [OK] Dependances installees
echo.

REM Compilation avec PyInstaller
echo ========================================================================
echo    COMPILATION EN COURS...
echo ========================================================================
echo.

pyinstaller --onefile ^
    --name "FULL_extraction_LB5_V1.1" ^
    --icon NONE ^
    --add-data "requirements.txt;." ^
    --clean ^
    --console ^
    FULL_extraction_LB5_V1.1.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERREUR] Echec de la compilation
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo    COMPILATION TERMINEE !
echo ========================================================================
echo.
echo Fichier genere : dist\FULL_extraction_LB5.exe
echo.
echo Pour utiliser :
echo   1. Copiez dist\FULL_extraction_LB5.exe ou vous voulez
echo   2. Double-cliquez dessus
echo   3. Suivez les instructions
echo.
echo Le .exe est standalone, pas besoin de Python installe !
echo.

pause
