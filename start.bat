@echo off
chcp 65001 > nul
title Yoxiko Port Scanner

echo.
echo ================================
echo     Yoxiko Port Scanner
echo ================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python не установлен или не добавлен в PATH
    echo Установите Python с python.org
    pause
    exit /b 1
)

echo Проверка зависимостей...
python -c "import socket, threading, concurrent.futures, ipaddress, re, time, argparse, sys, json, select, ssl, struct, datetime, logging, csv, os" 2>nul
if errorlevel 1 (
    echo ERROR: Отсутствуют необходимые библиотеки Python
    echo Установите: pip install socket threading concurrent.futures ipaddress re time argparse sys json select ssl struct datetime logging csv os
    pause
    exit /b 1
)

python -c "import tqdm" 2>nul
if errorlevel 1 (
    echo WARNING: tqdm не установлен. Для прогресс-бара установите: pip install tqdm
)

echo.
echo Запуск сканера...
echo.

python yoxiko.py %*

if errorlevel 1 (
    echo.
    echo ERROR: Произошла ошибка при выполнении скрипта
    pause
    exit /b 1
)

echo.
echo Сканирование завершено!
timeout /t 3 >nul