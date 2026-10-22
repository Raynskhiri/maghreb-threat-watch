import pytest

from mtw.config import load_allowlist, load_brands, load_settings
from mtw.matcher import Matcher


@pytest.fixture(scope="session")
def brands():
    return load_brands()


@pytest.fixture(scope="session")
def settings():
    return load_settings()


@pytest.fixture(scope="session")
def matcher(brands, settings):
    return Matcher(brands, settings, load_allowlist())
