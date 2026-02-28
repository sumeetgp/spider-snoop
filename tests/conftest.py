# Fix passlib 1.7.4 + bcrypt 5.0.0 incompatibility.
#
# passlib's _finalize_backend_mixin internally calls hashpw() with a 255-byte
# test password to check for the crypt_blowfish 8-bit wrap bug. bcrypt 5.0.0
# added strict enforcement of the 72-byte limit and raises ValueError for
# passwords longer than that, crashing passlib's backend initialization.
#
# We patch bcrypt.hashpw to silently truncate passwords > 72 bytes so passlib's
# internal tests pass. This does NOT affect application password hashing since
# real passwords are << 72 bytes.
try:
    import bcrypt as _bcrypt_mod
    _orig_hashpw = _bcrypt_mod.hashpw

    def _hashpw_compat(password, salt):
        if isinstance(password, str):
            password = password.encode("utf-8")
        if len(password) > 72:
            password = password[:72]
        return _orig_hashpw(password, salt)

    _bcrypt_mod.hashpw = _hashpw_compat
except Exception:
    pass

# Preserve real PIL modules before test collection corrupts them.
#
# test_supply_chain.py assigns sys.modules["PIL"] = MagicMock() at module
# level during collection. This corrupts PIL.ImageColor for all tests that
# run after it, causing "TypeError: color must be int or tuple" in tests
# that use PIL.Image (e.g. test_cdr.py, test_cdr_capabilities.py).
#
# Strategy: eagerly import PIL submodules here (before collection touches
# sys.modules) and store references. A session-scoped autouse fixture then
# restores any module that was replaced by a MagicMock during collection.
import sys as _sys

_pil_modules_to_preserve = [
    "PIL",
    "PIL.Image",
    "PIL.ImageColor",
    "PIL.ImageFile",
    "PIL.JpegImagePlugin",
    "PIL.PngImagePlugin",
    "PIL.ImageDraw",
    "PIL.ImageFont",
]

_preserved_pil = {}
try:
    import PIL as _pil_pkg  # noqa: F401 — side-effect: populates sys.modules
    import PIL.Image as _pil_image  # noqa: F401
    import PIL.ImageColor as _pil_ic  # noqa: F401
    for _mod_name in _pil_modules_to_preserve:
        if _mod_name in _sys.modules:
            _preserved_pil[_mod_name] = _sys.modules[_mod_name]
except Exception:
    pass

import pytest


@pytest.fixture(scope="session", autouse=True)
def restore_pil_sys_modules():
    """Restore real PIL modules that test collection may have replaced with mocks.

    test_supply_chain.py sets sys.modules['PIL'] = MagicMock() at the module
    level. This runs during pytest collection before any test fixture can
    intercept it. By the time tests execute, PIL is a MagicMock.

    This session-scoped fixture runs before any test and puts the real modules
    back so that tests relying on PIL (CDR, image OCR, etc.) work correctly.
    """
    for mod_name, real_mod in _preserved_pil.items():
        current = _sys.modules.get(mod_name)
        # Only restore if the current entry is a MagicMock (duck-check)
        if current is not real_mod:
            _sys.modules[mod_name] = real_mod
    yield
