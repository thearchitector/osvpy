"""Typed, immutable language coverage. OS extraction always remains enabled."""

from enum import Flag, auto
from types import MappingProxyType


class LanguageSelection(Flag):
    """Combine formats with |. Family presets include manifests and lockfiles."""

    NONE = 0
    CPP_CONAN = auto()
    DART_PUBSPEC = auto()
    DOTNET_PROJECT = auto()
    DOTNET_DEPS = auto()
    DOTNET_CENTRAL_PACKAGES = auto()
    DOTNET_PACKAGES_CONFIG = auto()
    DOTNET_PACKAGES_LOCK = auto()
    ELIXIR_MIX = auto()
    GO_BINARY = auto()
    GO_MODULES = auto()
    HASKELL_CABAL = auto()
    HASKELL_STACK = auto()
    JAVA_ARCHIVE = auto()
    JAVA_GRADLE_LOCK = auto()
    JAVA_GRADLE_VERIFICATION = auto()
    JAVA_MAVEN = auto()
    JAVASCRIPT_INSTALLED = auto()
    JAVASCRIPT_NPM = auto()
    JAVASCRIPT_PNPM = auto()
    JAVASCRIPT_YARN = auto()
    JAVASCRIPT_BUN = auto()
    PHP_COMPOSER = auto()
    PYTHON_INSTALLED = auto()
    PYTHON_REQUIREMENTS = auto()
    PYTHON_POETRY = auto()
    PYTHON_PIPFILE = auto()
    PYTHON_PDM = auto()
    PYTHON_PYLOCK = auto()
    PYTHON_UV = auto()
    R_RENV = auto()
    RUBY_GEMFILE = auto()
    RUST_BINARY = auto()
    RUST_CARGO = auto()
    SWIFT_PACKAGE_RESOLVED = auto()

    CPP = CPP_CONAN
    DART = DART_PUBSPEC
    DOTNET = (
        DOTNET_PROJECT
        | DOTNET_DEPS
        | DOTNET_CENTRAL_PACKAGES
        | DOTNET_PACKAGES_CONFIG
        | DOTNET_PACKAGES_LOCK
    )
    ELIXIR = ELIXIR_MIX
    GO = GO_BINARY | GO_MODULES
    HASKELL = HASKELL_CABAL | HASKELL_STACK
    JAVA = JAVA_ARCHIVE | JAVA_GRADLE_LOCK | JAVA_GRADLE_VERIFICATION | JAVA_MAVEN
    JAVASCRIPT = (
        JAVASCRIPT_INSTALLED
        | JAVASCRIPT_NPM
        | JAVASCRIPT_PNPM
        | JAVASCRIPT_YARN
        | JAVASCRIPT_BUN
    )
    PHP = PHP_COMPOSER
    PYTHON = (
        PYTHON_INSTALLED
        | PYTHON_REQUIREMENTS
        | PYTHON_POETRY
        | PYTHON_PIPFILE
        | PYTHON_PDM
        | PYTHON_PYLOCK
        | PYTHON_UV
    )
    R = R_RENV
    RUBY = RUBY_GEMFILE
    RUST = RUST_BINARY | RUST_CARGO
    SWIFT = SWIFT_PACKAGE_RESOLVED
    INSTALLED = (
        GO_BINARY | JAVA_ARCHIVE | JAVASCRIPT_INSTALLED | PYTHON_INSTALLED | RUST_BINARY
    )
    ALL = (
        CPP
        | DART
        | DOTNET
        | ELIXIR
        | GO
        | HASKELL
        | JAVA
        | JAVASCRIPT
        | PHP
        | PYTHON
        | R
        | RUBY
        | RUST
        | SWIFT
    )


_PLUGINS = MappingProxyType({
    LanguageSelection.CPP_CONAN: ("cpp/conanlock",),
    LanguageSelection.DART_PUBSPEC: ("dart/pubspec",),
    LanguageSelection.DOTNET_PROJECT: ("dotnet/csproj",),
    LanguageSelection.DOTNET_DEPS: ("dotnet/depsjson",),
    LanguageSelection.DOTNET_CENTRAL_PACKAGES: ("dotnet/nugetcpm",),
    LanguageSelection.DOTNET_PACKAGES_CONFIG: ("dotnet/packagesconfig",),
    LanguageSelection.DOTNET_PACKAGES_LOCK: ("dotnet/packageslockjson",),
    LanguageSelection.ELIXIR_MIX: ("elixir/mixlock",),
    LanguageSelection.GO_BINARY: ("go/binary",),
    LanguageSelection.GO_MODULES: ("go/gomod",),
    LanguageSelection.HASKELL_CABAL: ("haskell/cabal",),
    LanguageSelection.HASKELL_STACK: ("haskell/stacklock",),
    LanguageSelection.JAVA_ARCHIVE: ("java/archive",),
    LanguageSelection.JAVA_GRADLE_LOCK: ("java/gradlelockfile",),
    LanguageSelection.JAVA_GRADLE_VERIFICATION: ("java/gradleverificationmetadataxml",),
    LanguageSelection.JAVA_MAVEN: ("java/pomxml",),
    LanguageSelection.JAVASCRIPT_INSTALLED: ("javascript/nodemodules",),
    LanguageSelection.JAVASCRIPT_NPM: ("javascript/packagelockjson",),
    LanguageSelection.JAVASCRIPT_PNPM: ("javascript/pnpmlock",),
    LanguageSelection.JAVASCRIPT_YARN: ("javascript/yarnlock",),
    LanguageSelection.JAVASCRIPT_BUN: ("javascript/bunlock",),
    LanguageSelection.PHP_COMPOSER: ("php/composerlock",),
    LanguageSelection.PYTHON_INSTALLED: ("python/wheelegg",),
    LanguageSelection.PYTHON_REQUIREMENTS: ("python/requirements",),
    LanguageSelection.PYTHON_POETRY: ("python/poetrylock",),
    LanguageSelection.PYTHON_PIPFILE: ("python/pipfilelock",),
    LanguageSelection.PYTHON_PDM: ("python/pdmlock",),
    LanguageSelection.PYTHON_PYLOCK: ("python/pylock",),
    LanguageSelection.PYTHON_UV: ("python/uvlock",),
    LanguageSelection.R_RENV: ("r/renvlock",),
    LanguageSelection.RUBY_GEMFILE: ("ruby/gemfilelock",),
    LanguageSelection.RUST_BINARY: ("rust/cargoauditable",),
    LanguageSelection.RUST_CARGO: ("rust/cargolock",),
    LanguageSelection.SWIFT_PACKAGE_RESOLVED: ("swift/packageresolved",),
})


def resolve_languages(selection: LanguageSelection | None) -> tuple[str, ...]:
    if selection is None:
        selection = LanguageSelection.INSTALLED
    return tuple(
        plugin
        for flag, plugins in _PLUGINS.items()
        if flag in selection
        for plugin in plugins
    )
