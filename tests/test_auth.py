from pyosv import RegistryAuth


def test_credentials_are_excluded_from_repr() -> None:
    representation = repr(RegistryAuth("private-user", "secret-password"))
    assert "private-user" not in representation
    assert "secret-password" not in representation
