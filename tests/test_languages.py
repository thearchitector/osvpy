import pytest

from osvpy import LanguageSelection
from osvpy.languages import resolve_languages


@pytest.mark.parametrize(
    ("selection", "expected"),
    [
        (LanguageSelection.NONE, ()),
        (LanguageSelection.PYTHON_INSTALLED, ("python/wheelegg",)),
        (LanguageSelection.GO_MODULES, ("go/gomod",)),
    ],
)
def test_language_selection(
    selection: LanguageSelection, expected: tuple[str, ...]
) -> None:
    assert resolve_languages(selection) == expected


def test_default_selection_is_installed_languages() -> None:
    assert resolve_languages(None) == resolve_languages(LanguageSelection.INSTALLED)


def test_combined_selection_includes_both_languages() -> None:
    selection = LanguageSelection.PYTHON | LanguageSelection.JAVA
    assert set(resolve_languages(selection)) == (
        set(resolve_languages(LanguageSelection.PYTHON))
        | set(resolve_languages(LanguageSelection.JAVA))
    )


def test_all_languages_includes_every_selection() -> None:
    all_plugins = set(resolve_languages(LanguageSelection.ALL))
    for selection in LanguageSelection:
        assert set(resolve_languages(selection)) <= all_plugins


@pytest.mark.parametrize(
    ("selection", "expected"),
    [
        (LanguageSelection.CPP_CONAN, "cpp/conanlock"),
        (LanguageSelection.DART_PUBSPEC, "dart/pubspec"),
        (LanguageSelection.DOTNET_PROJECT, "dotnet/csproj"),
        (LanguageSelection.DOTNET_DEPS, "dotnet/depsjson"),
        (LanguageSelection.DOTNET_CENTRAL_PACKAGES, "dotnet/nugetcpm"),
        (LanguageSelection.DOTNET_PACKAGES_CONFIG, "dotnet/packagesconfig"),
        (LanguageSelection.DOTNET_PACKAGES_LOCK, "dotnet/packageslockjson"),
        (LanguageSelection.ELIXIR_MIX, "elixir/mixlock"),
        (LanguageSelection.GO_BINARY, "go/binary"),
        (LanguageSelection.GO_MODULES, "go/gomod"),
        (LanguageSelection.HASKELL_CABAL, "haskell/cabal"),
        (LanguageSelection.HASKELL_STACK, "haskell/stacklock"),
        (LanguageSelection.JAVA_ARCHIVE, "java/archive"),
        (LanguageSelection.JAVA_GRADLE_LOCK, "java/gradlelockfile"),
        (
            LanguageSelection.JAVA_GRADLE_VERIFICATION,
            "java/gradleverificationmetadataxml",
        ),
        (LanguageSelection.JAVA_MAVEN, "java/pomxml"),
        (LanguageSelection.JAVASCRIPT_INSTALLED, "javascript/nodemodules"),
        (LanguageSelection.JAVASCRIPT_NPM, "javascript/packagelockjson"),
        (LanguageSelection.JAVASCRIPT_PNPM, "javascript/pnpmlock"),
        (LanguageSelection.JAVASCRIPT_YARN, "javascript/yarnlock"),
        (LanguageSelection.JAVASCRIPT_BUN, "javascript/bunlock"),
        (LanguageSelection.PHP_COMPOSER, "php/composerlock"),
        (LanguageSelection.PYTHON_INSTALLED, "python/wheelegg"),
        (LanguageSelection.PYTHON_REQUIREMENTS, "python/requirements"),
        (LanguageSelection.PYTHON_POETRY, "python/poetrylock"),
        (LanguageSelection.PYTHON_PIPFILE, "python/pipfilelock"),
        (LanguageSelection.PYTHON_PDM, "python/pdmlock"),
        (LanguageSelection.PYTHON_PYLOCK, "python/pylock"),
        (LanguageSelection.PYTHON_UV, "python/uvlock"),
        (LanguageSelection.R_RENV, "r/renvlock"),
        (LanguageSelection.RUBY_GEMFILE, "ruby/gemfilelock"),
        (LanguageSelection.RUST_BINARY, "rust/cargoauditable"),
        (LanguageSelection.RUST_CARGO, "rust/cargolock"),
        (LanguageSelection.SWIFT_PACKAGE_RESOLVED, "swift/packageresolved"),
    ],
)
def test_each_language_format_selects_its_plugin(
    selection: LanguageSelection, expected: str
) -> None:
    assert resolve_languages(selection) == (expected,)
