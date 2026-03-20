"""Test fixtures for glassworm-hunter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_ioc_cache() -> None:
    """Ensure IoC cache is fresh for each test."""
    from glassworm_hunter.engine.ioc import reset_cache

    reset_cache()
    yield  # type: ignore[misc]
    reset_cache()


def _encode_to_variation_selectors(payload: str) -> str:
    """Encode a string into invisible variation selector characters."""
    result = []
    for byte in payload.encode("utf-8"):
        if byte < 16:
            # Use U+FE00-U+FE0F range
            result.append(chr(0xFE00 + byte))
        else:
            # Use U+E0100-U+E01EF range
            result.append(chr(0xE0100 + byte - 16))
    return "".join(result)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def malicious_unicode_content() -> str:
    """JavaScript with an invisible variation selector payload."""
    payload = 'console.log("glassworm-test-payload")'
    encoded = _encode_to_variation_selectors(payload)
    return f"const s = `{encoded}`;\n"


@pytest.fixture
def benign_emoji_content() -> str:
    """JavaScript with legitimate variation selector usage (emoji)."""
    # Heart emoji with variation selector (U+FE0F)
    return "const emoji = '\\u2764\\uFE0F';\nconsole.log(emoji);\n"


@pytest.fixture
def malicious_eval_content() -> str:
    """JavaScript with GlassWorm decoder pattern."""
    payload = 'console.log("test")'
    encoded = _encode_to_variation_selectors(payload)
    return (
        "const s = v => [...v].map(w => (\n"
        "  w = w.codePointAt(0),\n"
        "  w >= 0xFE00 && w <= 0xFE0F ? w - 0xFE00 :\n"
        "  w >= 0xE0100 && w <= 0xE01EF ? w - 0xE0100 + 16 : null\n"
        ")).filter(n => n !== null);\n"
        f"eval(Buffer.from(s(`{encoded}`)).toString('utf-8'));\n"
    )


@pytest.fixture
def suspicious_c2_content() -> str:
    """JavaScript with Solana RPC and credential access patterns."""
    return (
        "const connection = new Connection('https://api.mainnet-beta.solana.com');\n"
        "const sigs = await connection.getSignaturesForAddress(pubkey);\n"
        "const tx = await connection.getTransaction(sig);\n"
        "const npmrc = fs.readFileSync(path.join(homedir(), '.npmrc'), 'utf-8');\n"
        "const token = process.env['GITHUB_TOKEN'];\n"
    )


@pytest.fixture
def tmp_js_file(tmp_path: Path, malicious_unicode_content: str) -> Path:
    """Create a temporary JS file with malicious content."""
    f = tmp_path / "test.js"
    f.write_text(malicious_unicode_content, encoding="utf-8")
    return f


@pytest.fixture
def tmp_benign_js(tmp_path: Path, benign_emoji_content: str) -> Path:
    """Create a temporary JS file with benign emoji content."""
    f = tmp_path / "benign.js"
    f.write_text(benign_emoji_content, encoding="utf-8")
    return f


@pytest.fixture
def tmp_clean_dir(tmp_path: Path) -> Path:
    """Create a clean directory with no malicious content."""
    d = tmp_path / "clean_project"
    d.mkdir()
    (d / "index.js").write_text("console.log('hello');\n", encoding="utf-8")
    (d / "util.py").write_text("print('hello')\n", encoding="utf-8")
    (d / "README.md").write_text("# Clean Project\n", encoding="utf-8")
    return d


@pytest.fixture
def tmp_infected_dir(tmp_path: Path, malicious_unicode_content: str) -> Path:
    """Create a directory with malicious content."""
    d = tmp_path / "infected_project"
    d.mkdir()
    (d / "clean.js").write_text("console.log('ok');\n", encoding="utf-8")
    (d / "infected.js").write_text(malicious_unicode_content, encoding="utf-8")
    return d


@pytest.fixture
def tmp_extension_dir(tmp_path: Path) -> Path:
    """Create a mock VS Code extension directory."""
    ext_dir = tmp_path / "extensions"
    ext_dir.mkdir()

    # Clean extension
    clean = ext_dir / "publisher.clean-ext-1.0.0"
    clean.mkdir()
    (clean / "package.json").write_text(
        json.dumps(
            {
                "publisher": "publisher",
                "name": "clean-ext",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (clean / "extension.js").write_text("module.exports.activate = () => {};\n", encoding="utf-8")

    return ext_dir


@pytest.fixture
def tmp_malicious_extension(tmp_path: Path, malicious_unicode_content: str) -> Path:
    """Create a mock malicious VS Code extension."""
    ext_dir = tmp_path / "extensions"
    ext_dir.mkdir(exist_ok=True)

    mal = ext_dir / "codejoy.codejoy-vscode-extension-1.8.4"
    mal.mkdir()
    (mal / "package.json").write_text(
        json.dumps(
            {
                "publisher": "codejoy",
                "name": "codejoy-vscode-extension",
                "version": "1.8.4",
            }
        ),
        encoding="utf-8",
    )
    (mal / "extension.js").write_text(malicious_unicode_content, encoding="utf-8")

    return ext_dir


@pytest.fixture
def tmp_npm_dir(tmp_path: Path) -> Path:
    """Create a mock node_modules with a known malicious package."""
    project = tmp_path / "npm_project"
    project.mkdir()
    nm = project / "node_modules"
    nm.mkdir()

    # Clean package
    clean = nm / "lodash"
    clean.mkdir()
    (clean / "package.json").write_text(
        json.dumps(
            {
                "name": "lodash",
                "version": "4.17.21",
            }
        ),
        encoding="utf-8",
    )
    (clean / "index.js").write_text("module.exports = {};\n", encoding="utf-8")

    # Malicious package
    scoped = nm / "@aifabrix"
    scoped.mkdir()
    mal = scoped / "miso-client"
    mal.mkdir()
    (mal / "package.json").write_text(
        json.dumps(
            {
                "name": "@aifabrix/miso-client",
                "version": "4.7.2",
                "scripts": {"postinstall": "node setup.js"},
            }
        ),
        encoding="utf-8",
    )
    (mal / "index.js").write_text("module.exports = {};\n", encoding="utf-8")

    return project
