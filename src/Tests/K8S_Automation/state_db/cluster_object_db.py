import sqlite3
from pathlib import Path

from globals.global_strings import global_strings


class ClusterObjectDb:
    def __init__(self, db_path: Path):
        self._db_path = str(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS manifests (
                    name TEXT PRIMARY KEY
                )
                """
            )

    def add(self, manifest_name: str) -> None:
        with sqlite3.connect(self._db_path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO manifests (name) VALUES (?)",
                (manifest_name,),
            )

    def get_all(self) -> list[str]:
        with sqlite3.connect(self._db_path) as connection:
            cursor = connection.execute("SELECT name FROM manifests ORDER BY name")
            return [row[0] for row in cursor.fetchall()]

    def remove_all(self) -> None:
        with sqlite3.connect(self._db_path) as connection:
            connection.execute("DELETE FROM manifests")


cluster_object_db = ClusterObjectDb(global_strings.AUTOMATION_ROOT_DIR / "cluster_object_db.sqlite")
