"""SQL 词法解析器 — 基于 sqlparse 的 SQL 语句分析，防止注释混淆绕过。"""

import re
from dataclasses import dataclass, field

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import Identifier

DDL_KEYWORDS = frozenset({"CREATE", "DROP", "ALTER", "TRUNCATE", "RENAME"})
DCL_KEYWORDS = frozenset({"GRANT", "REVOKE"})

# MySQL 条件注释是已知的 SQL 注入绕过手段: /*!12345 DROP TABLE users */
_MYSQL_COND_COMMENT_RE = re.compile(r'/\*![0-9]*\s*(.*?)\*/', re.DOTALL)


def _is_keyword(ttype: T._TokenType) -> bool:
    """检查 token 类型是否为 Keyword 及其子类型（DDL/DCL/DML）。"""
    while ttype is not None:
        if ttype is T.Keyword:
            return True
        ttype = getattr(ttype, 'parent', None)
    return False


@dataclass
class SqlAnalysis:
    """SQL 分析结果。"""
    has_ddl: bool = False
    has_dcl: bool = False
    tables_touched: list[str] = field(default_factory=list)
    statement_types: list[str] = field(default_factory=list)


class SqlParser:
    """SQL 词法解析器 — 先提取 MySQL 条件注释，再去掉普通注释，然后解析。"""

    def _extract_mysql_conditional(self, sql_text: str) -> str:
        parts: list[str] = []
        def _replacer(match: re.Match) -> str:
            content = match.group(1).strip()
            if content:
                parts.append(content)
            return ""
        cleaned = _MYSQL_COND_COMMENT_RE.sub(_replacer, sql_text)
        if parts:
            cleaned = cleaned + " " + "; ".join(parts)
        return cleaned

    def analyze(self, sql_text: str) -> SqlAnalysis:
        cleaned = self._extract_mysql_conditional(sql_text)
        cleaned = sqlparse.format(cleaned, strip_comments=True)
        parsed = sqlparse.parse(cleaned)

        result = SqlAnalysis()
        for statement in parsed:
            stype = statement.get_type()
            if stype and stype != "UNKNOWN":
                result.statement_types.append(stype)

            for token in statement.flatten():
                if not _is_keyword(token.ttype):
                    continue
                val = token.value.upper()
                if val in DDL_KEYWORDS:
                    result.has_ddl = True
                if val in DCL_KEYWORDS:
                    result.has_dcl = True

            for token in statement.tokens:
                if isinstance(token, Identifier):
                    name = token.get_real_name()
                    if name and name not in result.tables_touched:
                        result.tables_touched.append(name)

        return result
