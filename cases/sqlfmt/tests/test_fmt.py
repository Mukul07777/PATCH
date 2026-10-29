from sqlfmt import fmt


def test_keywords_upper():
    assert fmt.pretty("select a from t where b = 1").startswith("SELECT")


def test_split():
    assert fmt.statements("select 1; select 2;") == ["select 1;", "select 2;"]


def test_type():
    assert fmt.first_keyword("UPDATE t SET a = 1") == "UPDATE"
    assert fmt.first_keyword("select 1") == "SELECT"
