"""Test search with ldaputil.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio

import pytest

from config import Settings
from tests.conftest import TestCreds


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("session")
async def test_ldap_search(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{settings.HOST}:{settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split("\n")
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: cn=users,dc=md,dc=test" in data
    assert "dn: cn=user0,cn=users,dc=md,dc=test" in data


@pytest.mark.asyncio
@pytest.mark.usefixtures("setup_session")
@pytest.mark.usefixtures("_global_server")
async def test_global_ldap_search(
    global_settings: Settings,
    creds: TestCreds,
) -> None:
    """Test ldapsearch on server."""
    print("OLOLO 00000")
    print(
        global_settings.HOST,
        global_settings.PORT,
        "\n\n",
        creds.un,
        creds.pw,
    )

    # Проверка что порты слушаются
    netstat_proc = await asyncio.create_subprocess_exec(
        "netstat",
        "-tuln",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    netstat_out, _ = await netstat_proc.communicate()
    print("NETSTAT OUTPUT:")
    print(netstat_out.decode())
    print("=" * 50)

    # Используем 127.0.0.1 для подключения (0.0.0.0 это bind адрес, не connect)
    host = (
        "127.0.0.1"
        if str(global_settings.HOST) == "0.0.0.0"
        else str(global_settings.HOST)
    )

    # Сначала проверим что порт доступен через telnet
    print(f"Testing TCP connection to {host}:{global_settings.PORT}...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, global_settings.PORT),
            timeout=2.0,
        )
        print("✓ TCP connection successful!")
        writer.close()
        await writer.wait_closed()
    except TimeoutError:
        print("✗ TCP connection timeout!")
    except Exception as e:
        print(f"✗ TCP connection failed: {e}")

    print(f"Running ldapsearch to {host}:{global_settings.PORT}...")

    # Подождем еще чтобы сервер точно готов
    await asyncio.sleep(2)

    # Сначала проверим что обычный LDAP на 389 работает
    print("Testing regular LDAP on port 389 first...")
    proc_389 = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-x",
        "-H",
        f"ldap://{host}:389",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "-s",
        "base",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        data_389, err_389 = await asyncio.wait_for(
            proc_389.communicate(),
            timeout=5.0,
        )
        result_389 = await proc_389.wait()
        print(f"✓ Port 389 works! Result: {result_389}")
    except TimeoutError:
        print("✗ Port 389 also timeout!")
        proc_389.kill()

    print("Now testing global LDAP on port 3268...")
    proc = await asyncio.create_subprocess_exec(
        "ldapsearch",
        "-vvv",
        "-x",
        "-H",
        f"ldap://{host}:{global_settings.PORT}",
        "-D",
        creds.un,
        "-w",
        creds.pw,
        "-b",
        "dc=md,dc=test",
        "objectclass=*",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    print("ldapsearch process started, waiting for response...")

    try:
        raw_data, raw_err = await asyncio.wait_for(
            proc.communicate(),
            timeout=10.0,
        )
        data = raw_data.decode().split("\n")
        err = raw_err.decode().split("\n")
        result = await proc.wait()
    except TimeoutError:
        print("✗ ldapsearch timeout after 10 seconds!")
        proc.kill()
        raise

    print("OLOLO")
    print("STDOUT:", data)
    print("STDERR:", err)
    print("RESULT:", result)
    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: cn=users,dc=md,dc=test" in data
    assert "dn: cn=user0,cn=users,dc=md,dc=test" in data
