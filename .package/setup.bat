@echo off
setlocal enabledelayedexpansion

:: Создаем .env файл если не существует
if not exist ".env" type nul > .env

:: Удаляем пустые переменные из файла
findstr /v /r /c:"^[^=]*=$" .env > .env.tmp
move /y .env.tmp .env >nul

:: ========== ОПРЕДЕЛЕНИЕ ПЕРЕМЕННЫХ ==========

:: 1. DEFAULT_NAMESERVER
findstr /b /i /c:"DEFAULT_NAMESERVER=" .env >nul
if errorlevel 1 (
    :nameserver_loop
    set "server_ip="
    set /p "server_ip=Enter host server ip address: "
    if defined server_ip (
        echo DEFAULT_NAMESERVER=!server_ip!>> .env
    ) else (
        echo Host server ip address required.
        goto nameserver_loop
    )
)

:: 2. POSTGRES_USER
findstr /b /i /c:"POSTGRES_USER=" .env >nul
if errorlevel 1 (
    set "postgres_user="
    set /p "postgres_user=Enter postgres user [default: user]: "
    if not defined postgres_user set "postgres_user=user"
    echo POSTGRES_USER=!postgres_user!>> .env
)

:: 3. POSTGRES_DB
findstr /b /i /c:"POSTGRES_DB=" .env >nul
if errorlevel 1 (
    set "postgres_db="
    set /p "postgres_db=Enter postgres database name [default: postgres]: "
    if not defined postgres_db set "postgres_db=postgres"
    echo POSTGRES_DB=!postgres_db!>> .env
)

:: 4. POSTGRES_HOST
findstr /b /i /c:"POSTGRES_HOST=" .env >nul
if errorlevel 1 (
    set "postgres_host="
    set /p "postgres_host=Enter postgres host [default: postgres]: "
    if not defined postgres_host set "postgres_host=postgres"
    echo POSTGRES_HOST=!postgres_host!>> .env
)

:: 5. POSTGRES_PASSWORD
findstr /b /i /c:"POSTGRES_PASSWORD=" .env >nul
if errorlevel 1 (
    set "postgres_password="
    set /p "postgres_password=Enter postgres password [default: autogenerate]: "
    if not defined postgres_password (
        set "chars=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        set "pass="
        for /L %%i in (1,1,32) do (
            set /a "rand=!random! %% 62"
            for %%j in (!rand!) do set "pass=!pass!!chars:~%%j,1!"
        )
        set "postgres_password=!pass!"
    )
    echo POSTGRES_PASSWORD=!postgres_password!>> .env
)

:: 6. DOMAIN
findstr /b /i /c:"DOMAIN=" .env >nul
if errorlevel 1 (
    :domain_loop
    set "domain="
    set /p "domain=Enter interface domain [required]: "
    if defined domain (
        echo DOMAIN=!domain!>> .env
    ) else (
        echo Interface domain required.
        goto domain_loop
    )
)

:: 7. SECRET_KEY
findstr /b /i /c:"SECRET_KEY=" .env >nul
if errorlevel 1 (
    set "chars=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    set "secret="
    for /L %%i in (1,1,64) do (
        set /a "rand=!random! %% 62"
        for %%j in (!rand!) do set "secret=!secret!!chars:~%%j,1!"
    )
    echo SECRET_KEY=!secret!>> .env
)
