from mtw.normalize import compact, fold, leet_variants, skeletons


def test_fold_maps_cyrillic_and_greek_lookalikes():
    assert fold("biаt") == "biat"          # Cyrillic а
    assert fold("ооredoo") == "ooredoo"    # Cyrillic о о
    assert fold("ΒΙΑΤ".lower()) == "biat"  # Greek capitals lowered


def test_fold_strips_accents_and_fullwidth():
    assert fold("bíat") == "biat"
    assert fold("ＢＩＡＴ") == "biat"


def test_leet_one_is_ambiguous():
    assert leet_variants("b1at") == {"biat", "blat"}
    assert leet_variants("amenb4nk") == {"amenbank"}


def test_skeletons_include_multi_letter_lookalikes():
    assert "amenbank" in skeletons("arnenbank")


def test_compact_removes_separators():
    assert compact("biat-secure.login_x") == "biatsecureloginx"
