"""Pretty-print and split SQL from query logs."""
import sqlparse


def pretty(sql):
    return sqlparse.format(sql, reindent=True, keyword_case="upper").strip()


def statements(sql):
    return [s.strip() for s in sqlparse.split(sql) if s.strip()]


def first_keyword(sql):
    return sqlparse.parse(sql)[0].get_type()
