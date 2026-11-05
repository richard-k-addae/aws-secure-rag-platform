from app.core.security import STRIPPED_CODE_POINT_RANGES, exceeds_limit, sanitize_text


def test_sanitize_strips_control_characters() -> None:
    assert sanitize_text("a\x00b\x08c\x1bd") == "abcd"


def test_sanitize_preserves_newlines_and_tabs() -> None:
    assert sanitize_text("line one\nline two\ttabbed") == "line one\nline two\ttabbed"


def test_sanitize_strips_every_code_point_in_policy() -> None:
    for start, end in STRIPPED_CODE_POINT_RANGES:
        for code_point in {start, end, (start + end) // 2}:
            assert sanitize_text(f"a{chr(code_point)}b") == "ab", hex(code_point)


def test_sanitize_preserves_legitimate_joiners_and_marks() -> None:
    # ZWNJ, ZWJ, LRM, RLM, ALM and the Mongolian vowel separator stay.
    for code_point in (0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x180E):
        assert sanitize_text(f"a{chr(code_point)}b") == f"a{chr(code_point)}b", hex(code_point)


def test_exceeds_limit() -> None:
    assert exceeds_limit("abc", 2)
    assert not exceeds_limit("abc", 3)
