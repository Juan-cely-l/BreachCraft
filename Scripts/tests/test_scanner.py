import pytest

from scanner import parse_ports


def test_parse_ports_accepts_ranges_lists_and_mixes() -> None:
    assert parse_ports("22,80,100-102,80") == [22, 80, 100, 101, 102]


@pytest.mark.parametrize("value", ["", "0", "65536", "10-1", "22,,80", "abc"])
def test_parse_ports_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(value)
