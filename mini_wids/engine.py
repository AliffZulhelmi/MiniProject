
"""Analysis orchestration entry point.

Provides a minimal `process_pcap` helper used by integration tests and small
tooling utilities. This module adds structured logging and defensive error
handling so the caller can run detectors on noisy capture files without
failing the whole run when a single detector errors.
"""

from typing import Any, Dict, Iterable
import logging
import os
import time

logger = logging.getLogger(__name__)


def _safe_import_detectors():
	# Import detector adapters lazily so an import-time failure in scapy or
	# other optional deps doesn't block module import.
	try:
		from mini_wids.detectors.deauth import detect_deauth_from_scapy
		from mini_wids.detectors.rogue_ap import detect_rogue_aps_from_scapy
		from mini_wids.detectors.unknown_device import detect_unknown_devices_from_scapy
		from mini_wids.detectors.weak_encryption import detect_weak_encryption_from_scapy
	except Exception as exc:  # pragma: no cover - defensive
		logger.exception("Failed to import detector adapters: %s", exc)
		raise

	return {
		"deauth": (detect_deauth_from_scapy, {}),
		"rogue_ap": (detect_rogue_aps_from_scapy, {}),
		"unknown_device": (detect_unknown_devices_from_scapy, {}),
		"weak_encryption": (detect_weak_encryption_from_scapy, {}),
	}


def process_pcap(pcap_path: str, deauth_threshold: int = 5, max_packets: int | None = None) -> Dict[str, Any]:
	"""Read `pcap_path` with scapy and run available detectors.

	Args:
		pcap_path: Path to a pcap file readable by scapy.
		deauth_threshold: Threshold forwarded to the deauth detector.
		max_packets: If set, limit processing to the first N packets.

	Returns:
		A mapping of detector name to their result (list of alerts) or an
		`error` entry when a detector fails.
	"""
	if not os.path.exists(pcap_path):
		logger.error("pcap path does not exist: %s", pcap_path)
		raise FileNotFoundError(pcap_path)

	try:
		from scapy.all import rdpcap  # type: ignore
	except Exception as exc:  # pragma: no cover - scapy required when used
		logger.exception("scapy is required to process pcaps: %s", exc)
		raise RuntimeError("scapy is required to process pcaps") from exc

	start = time.time()
	try:
		pkts = rdpcap(pcap_path)
	except Exception as exc:
		logger.exception("Failed to read pcap %s: %s", pcap_path, exc)
		raise

	total_packets = len(pkts)
	logger.info("Read %d packets from %s", total_packets, pcap_path)

	if max_packets is not None and max_packets > 0:
		pkts = pkts[:max_packets]
		logger.info("Limiting to first %d packets", len(pkts))

	detectors = _safe_import_detectors()

	results: Dict[str, Any] = {}

	# Run detectors one by one and isolate failures per-detector.
	for name, (func, extra_kwargs) in detectors.items():
		kwargs = dict(extra_kwargs)  # copy
		if name == "deauth":
			kwargs["threshold"] = deauth_threshold

		logger.debug("Running detector %s with kwargs=%s", name, kwargs)
		t0 = time.time()
		try:
			res = func(pkts, **kwargs)
			results[name] = res
			elapsed = time.time() - t0
			logger.info("Detector %s completed: %d results (%.2fs)", name, len(res) if isinstance(res, Iterable) else 1, elapsed)
		except Exception as exc:
			logger.exception("Detector %s failed: %s", name, exc)
			results[name] = {"error": str(exc)}

	total_elapsed = time.time() - start
	logger.info("Finished processing %s in %.2fs", pcap_path, total_elapsed)

	return results


def _format_results_for_storage(results: Dict[str, Any]):
	out = []
	for det, vals in results.items():
		if isinstance(vals, dict) and vals.get("error"):
			out.append({"detector": det, "error": vals.get("error")})
			continue
		# assume iterable of alerts
		try:
			for v in vals:
				if isinstance(v, dict):
					copy = dict(v)
				else:
					copy = {"value": v}
				copy["detector"] = det
				out.append(copy)
		except Exception:
			out.append({"detector": det, "value": str(vals)})
	return out


def _cli():
	import argparse

	parser = argparse.ArgumentParser(description="Process a PCAP and run Mini WIDS detectors")
	parser.add_argument("pcap", help="Path to pcap/pcapng file")
	parser.add_argument("--max-packets", type=int, default=None)
	parser.add_argument("--deauth-threshold", type=int, default=5)
	parser.add_argument("--save", action="store_true", help="Save alerts to repository")
	args = parser.parse_args()

	results = process_pcap(args.pcap, deauth_threshold=args.deauth_threshold, max_packets=args.max_packets)
	import json

	print(json.dumps(results, indent=2))

	if args.save:
		try:
			from mini_wids.storage.repository import save_alerts

			save_alerts(_format_results_for_storage(results))
			print("Saved alerts to repository")
		except Exception as exc:
			print("Failed to save alerts:", exc)


if __name__ == "__main__":
	_cli()


