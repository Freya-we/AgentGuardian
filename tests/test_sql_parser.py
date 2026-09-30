from src.engine.sql_parser import SqlParser


class TestSqlParser:
    def test_select_only_no_ddl(self):
        result = SqlParser().analyze("SELECT * FROM users")
        assert result.has_ddl is False
        assert result.has_dcl is False

    def test_drop_table_is_ddl(self):
        result = SqlParser().analyze("DROP TABLE audit_log")
        assert result.has_ddl is True
        assert "audit_log" in result.tables_touched

    def test_comment_obfuscation_bypassed(self):
        # /*!50000 DROP TABLE users*/ 不应被注释绕过
        result = SqlParser().analyze(
            "SELECT * FROM users; /*!50000 DROP TABLE users*/"
        )
        assert result.has_ddl is True

    def test_line_comment_ignored(self):
        result = SqlParser().analyze(
            "SELECT * FROM users -- DROP TABLE x\nWHERE id=1"
        )
        assert result.has_ddl is False

    def test_grant_is_dcl(self):
        result = SqlParser().analyze("GRANT SELECT ON users TO alice")
        assert result.has_dcl is True

    def test_multiple_statements(self):
        result = SqlParser().analyze(
            "SELECT * FROM a; DROP TABLE b; CREATE TABLE c(id INT)"
        )
        assert result.has_ddl is True
        assert len(result.statement_types) == 3
