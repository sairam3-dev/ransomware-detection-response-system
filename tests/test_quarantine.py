
import hashlib
from pathlib import Path

from app.response.quarantine import quarantine_file


def test_quarantine_copies_file_without_changing_original(
    tmp_path, monkeypatch
):
    """Verify quarantine copies evidence and preserves the original."""
    # Create an isolated temporary sandbox.
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    source = sandbox / "evidence.txt"
    original_content = b"Harmless RDRS quarantine test evidence."
    source.write_bytes(original_content)

    # Run quarantine from a temporary working directory.
    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(
        "app.response.quarantine.load_config",
        lambda: {
            "app": {"simulation_mode": True},
            "monitoring": {
                "watch_paths": [str(sandbox)],
            },
        },
    )

    # Call the actual quarantine implementation.
    result = quarantine_file(source)

    # Confirm the operation succeeded.
    assert result["success"] is True
    assert result["already_exists"] is False

    # Confirm the original remains unchanged.
    assert source.is_file()
    assert source.read_bytes() == original_content

    # Check the destination reported by the implementation.
    destination = Path(result["destination"])

    assert destination.is_file()
    assert destination.parent == (
        tmp_path / "data" / "quarantine"
    ).resolve()

    # Confirm the copied evidence matches the original.
    assert destination.read_bytes() == original_content

    # Confirm the destination filename contains the SHA-256 hash.
    expected_hash = hashlib.sha256(original_content).hexdigest()
    assert destination.name == f"{expected_hash}_evidence.txt"


def test_quarantine_rejects_file_outside_watched_folder(
    tmp_path, monkeypatch
):
    """Verify files outside watched folders are rejected."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    outside_file = tmp_path / "outside.txt"
    original_content = "Harmless test file."
    outside_file.write_text(original_content)

    monkeypatch.chdir(tmp_path)

    monkeypatch.setattr(
        "app.response.quarantine.load_config",
        lambda: {
            "app": {"simulation_mode": True},
            "monitoring": {
                "watch_paths": [str(sandbox)],
            },
        },
    )

    result = quarantine_file(outside_file)

    assert result["success"] is False
    assert result["reason"] == (
        "File is outside configured watch folders."
    )

    # The rejected file must remain unchanged.
    assert outside_file.read_text() == original_content

    # No quarantine copy should be created for the rejected file.
    assert not (tmp_path / "data" / "quarantine").exists()
