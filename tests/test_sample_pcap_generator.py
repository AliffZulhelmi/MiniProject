# ruff: noqa: S101

from __future__ import annotations

import builtins
from pathlib import Path

import pytest

from mini_wids.engine import process_pcap
from mini_wids import sample_pcap_generator as generator


def test_random_demo_seed_uses_urandom_entropy(monkeypatch):
    calls = []

    def fake_urandom(size: int) -> bytes:
        calls.append(size)
        return b"\x00\x00\x00*"

    monkeypatch.setattr(generator.os, "urandom", fake_urandom)

    assert generator.random_demo_seed() == 42
    assert calls == [4]


def test_next_demo_pcap_path_prefix(tmp_path):
    path = generator.next_demo_pcap_path(tmp_path, prefix="random_capture")

    assert path == tmp_path / "random_capture_0001.pcap"


def test_next_demo_pcap_path_increments(tmp_path):
    first = generator.next_demo_pcap_path(tmp_path, prefix="deauth_capture")
    first.touch()

    second = generator.next_demo_pcap_path(tmp_path, prefix="deauth_capture")

    assert second == tmp_path / "deauth_capture_0002.pcap"


@pytest.mark.parametrize("bad_prefix", ["", "   ", "../evil", "nested/path"])
def test_next_demo_pcap_path_rejects_bad_prefix(tmp_path, bad_prefix):
    with pytest.raises(ValueError, match="Invalid pcap prefix"):
        generator.next_demo_pcap_path(tmp_path, prefix=bad_prefix)


def test_next_demo_pcap_path_exhaustion(tmp_path, monkeypatch):
    existing = tmp_path / "random_capture_0001.pcap"
    existing.touch()

    def tiny_range(start: int, stop: int):
        assert (start, stop) == (1, 10000)
        return builtins.range(1, 2)

    monkeypatch.setattr(generator, "range", tiny_range, raising=False)

    with pytest.raises(RuntimeError, match="Exhausted 9999 pcap slots"):
        generator.next_demo_pcap_path(tmp_path, prefix="random_capture")


def test_build_alert_type_deauth_only():
    packets = generator.build_alert_type_packets("deauth", seed=42)

    assert packets


def test_build_alert_type_unknown_device():
    packets = generator.build_alert_type_packets("unknown_device", seed=42)

    assert packets


def test_build_alert_type_invalid_raises():
    with pytest.raises(ValueError, match="Unknown alert_type"):
        generator.build_alert_type_packets("invalid_type", seed=42)


def test_write_alert_type_pcap_naming(tmp_path):
    result = generator.write_alert_type_pcap("rogue_ap", output_dir=tmp_path, seed=99)

    assert result.path.name.startswith("rogue-ap_capture_")
    assert result.path.name.endswith(".pcap")
    assert result.path.exists()
    assert result.seed == 99


def test_write_numbered_demo_pcap_unique(tmp_path, monkeypatch):
    seeds = iter([101, 202])
    monkeypatch.setattr(generator, "random_demo_seed", lambda: next(seeds))

    first = generator.write_numbered_demo_pcap(output_dir=tmp_path)
    second = generator.write_numbered_demo_pcap(output_dir=tmp_path)

    assert first.path != second.path
    assert first.seed != second.seed
    assert first.path.name == "random_capture_0001.pcap"
    assert second.path.name == "random_capture_0002.pcap"


def test_write_alert_type_pcap_unique(tmp_path, monkeypatch):
    seeds = iter([303, 404])
    monkeypatch.setattr(generator, "random_demo_seed", lambda: next(seeds))

    first = generator.write_alert_type_pcap("deauth", output_dir=tmp_path)
    second = generator.write_alert_type_pcap("deauth", output_dir=tmp_path)

    assert first.path.name == "deauth_capture_0001.pcap"
    assert second.path.name == "deauth_capture_0002.pcap"
    assert first.seed != second.seed


def test_mixed_prefix_counters_independent(tmp_path):
    random_result = generator.write_numbered_demo_pcap(output_dir=tmp_path, seed=1)
    deauth_result = generator.write_alert_type_pcap(
        "deauth", output_dir=tmp_path, seed=2
    )

    assert random_result.path.name == "random_capture_0001.pcap"
    assert deauth_result.path.name == "deauth_capture_0001.pcap"


def test_alert_type_slugs_are_filename_safe():
    for slug in generator.ALERT_TYPE_SLUGS.values():
        assert Path(slug).name == slug
        assert "/" not in slug
        assert "\\" not in slug


@pytest.mark.parametrize(
    ("alert_type", "target_detector"),
    [
        ("deauth", "deauth"),
        ("rogue_ap", "rogue_ap"),
        ("weak_encryption", "weak_encryption"),
        ("unknown_device", "unknown_device"),
    ],
)
def test_alert_type_pcaps_trigger_only_target_detector(
    tmp_path, alert_type, target_detector
):
    generated = generator.write_alert_type_pcap(
        alert_type, output_dir=tmp_path, seed=42
    )

    counts = {
        detector: len(alerts)
        for detector, alerts in process_pcap(str(generated.path)).items()
    }

    assert counts[target_detector] > 0
    for detector, count in counts.items():
        if detector != target_detector:
            assert count == 0
