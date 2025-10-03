#!/usr/bin/env python3
"""Тест для проверки исправления миграций."""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "app"))


def test_migration_chain() -> bool:
    """Проверяем, что цепочка миграций корректна."""
    # Читаем файлы миграций и проверяем зависимости
    migrations_dir = os.path.join(
        os.path.dirname(__file__), "app", "alembic", "versions"
    )

    # Ключевые миграции для проверки
    key_migrations = {
        "8164b4a9e1f1": "add_ou_computers",
        "4798b12b97aa": "dedicated_servers",
        "eeaed5989eb0": "group_policies",
        "e4d6d99d32bd": "add_audit_policies",
    }

    # Проверяем зависимости
    dependencies = {}
    for rev_id, desc in key_migrations.items():
        file_path = os.path.join(migrations_dir, f"{rev_id}_{desc}.py")
        if os.path.exists(file_path):
            with open(file_path) as f:
                content = f.read()
                # Ищем down_revision
                for line in content.split("\n"):
                    if (
                        "down_revision =" in line
                        and not line.strip().startswith("#")
                    ):
                        down_rev = (
                            line.split('"')[1]
                            if '"' in line
                            else line.split("'")[1]
                        )
                        dependencies[rev_id] = down_rev
                        break

    print("=== Проверка цепочки миграций ===")
    print(f"Зависимости: {dependencies}")

    # Проверяем, что 8164b4a9e1f1 зависит от 4798b12b97aa
    if dependencies.get("8164b4a9e1f1") == "4798b12b97aa":
        print(
            "✅ 8164b4a9e1f1 (add_ou_computers) правильно зависит от 4798b12b97aa (dedicated_servers)"
        )
    else:
        print(
            f"❌ 8164b4a9e1f1 зависит от {dependencies.get('8164b4a9e1f1')}, ожидалось 4798b12b97aa"
        )
        return False

    # Проверяем, что 4798b12b97aa зависит от eeaed5989eb0
    if dependencies.get("4798b12b97aa") == "eeaed5989eb0":
        print(
            "✅ 4798b12b97aa (dedicated_servers) правильно зависит от eeaed5989eb0 (group_policies)"
        )
    else:
        print(
            f"❌ 4798b12b97aa зависит от {dependencies.get('4798b12b97aa')}, ожидалось eeaed5989eb0"
        )
        return False

    print("\n✅ Цепочка миграций исправлена корректно!")
    return True


if __name__ == "__main__":
    success = test_migration_chain()
    sys.exit(0 if success else 1)
