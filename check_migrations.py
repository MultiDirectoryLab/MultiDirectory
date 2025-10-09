#!/usr/bin/env python3
"""Скрипт для проверки цепочки миграций Alembic."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "app"))

from alembic.config import Config
from alembic.script import ScriptDirectory


def check_migrations() -> bool:
    config = Config("app/alembic.ini")
    script = ScriptDirectory.from_config(config)

    print("=== Проверка миграций ===")
    print(f"Heads: {script.get_heads()}")
    print(f"Current head: {script.get_current_head()}")

    # Проверим цепочку от текущей головы
    heads = script.get_heads()
    if len(heads) > 1:
        print(f"❌ ОШИБКА: Найдено {len(heads)} голов: {heads}")
        return False
    elif len(heads) == 0:
        print("❌ ОШИБКА: Не найдено голов")
        return False
    else:
        print(f"✅ Найдена одна голова: {heads[0]}")

    # Проверим цепочку миграций
    current_rev = heads[0]
    chain = []

    while current_rev:
        chain.append(current_rev)
        rev = script.get_revision(current_rev)
        if rev and rev.down_revision:
            current_rev = rev.down_revision  # type: ignore
        else:
            break

    print("\n=== Цепочка миграций (от головы к корню) ===")
    for i, rev_id in enumerate(chain):
        print(f"{i + 1}. {rev_id}")

    print("\n✅ Цепочка миграций корректна!")
    return True


if __name__ == "__main__":
    success = check_migrations()
    sys.exit(0 if success else 1)
