@echo off
chcp 65001 > nul
title Yoxiko Scanner
echo.
echo ================================
echo      YOXIKO PORT SCANNER
echo ================================
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python не установлен или не добавлен в PATH
    echo Скачайте Python с python.org
    pause
    exit /b 1
)

echo Проверка зависимостей...
python -c "import socket, threading, concurrent.futures, ipaddress, re, time, argparse, sys, json, select, ssl, struct, datetime, logging, csv, os" 2>nul
if errorlevel 1 (
    echo ERROR: Отсутствуют базовые библиотеки Python
    echo Установите необходимые пакеты
    pause
    exit /b 1
)


echo.
echo Запуск Yoxiko Scanner...
echo.
python yoxiko.py %*

if errorlevel 1 (
    echo.
    echo Сканирование завершено с ошибками
    pause
    exit /b 1
)

echo.
echo Сканирование завершено успешно!
timeout /t 3 >nul