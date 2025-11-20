"""Test Password Ban Word router.

Copyright (c) 2025 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import io

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_upload_ban_words_txt_success(http_client: AsyncClient) -> None:
    """Test uploading a .txt file with banned words."""
    file_content = "badword1\nbadword2\nbadword3\n"
    files = {
        "file": (
            "banwords.txt",
            io.BytesIO(file_content.encode("utf-8")),
            "text/plain",
        ),
    }
    response = await http_client.post(
        "/password_ban_word/upload_txt",
        files=files,
    )

    assert response.status_code == 201


@pytest.mark.asyncio
async def test_upload_ban_words_txt_400(http_client: AsyncClient) -> None:
    """Test uploading a file with an incorrect extension."""
    file_content = "badword1\nbadword2\n"
    files = {
        "file": (
            "banwords.csv",
            io.BytesIO(file_content.encode("utf-8")),
            "text/plain",
        ),
    }

    response = await http_client.post(
        "/password_ban_word/upload_txt",
        files=files,
    )

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_download_ban_words_txt(http_client: AsyncClient) -> None:
    """Test downloading a .txt file with banned words."""
    file_content = "banword1\nbanword2\nbanword3\n"
    files = {
        "file": (
            "banwords.txt",
            io.BytesIO(file_content.encode("utf-8")),
            "text/plain",
        ),
    }
    response = await http_client.post(
        "/password_ban_word/upload_txt",
        files=files,
    )

    response = await http_client.get("/password_ban_word/download_txt")
    assert response.status_code == 200

    content = response.content.decode("utf-8")
    lines = content.strip().split("\n")
    assert len(lines) == 3
    assert "banword1" in lines
    assert "banword2" in lines
    assert "banword3" in lines
