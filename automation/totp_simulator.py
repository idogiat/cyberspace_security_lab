#!/usr/bin/env python3
"""TOTP simulator

Generates TOTP codes from `src/users.json` using `pyotp` and can optionally
simulate CAPTCHA requirements by calling an admin endpoint.

Usage examples:
  python automation/totp_simulator.py --users-file src/users.json
  python automation/totp_simulator.py --captcha-rate 20 --group-seed seed123 --admin-url http://localhost:5000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from typing import Any, Dict, List, Optional

import pyotp
import requests


def load_users(path: str) -> tuple[List[Dict[str, Any]], Optional[str]]:
	"""Load users and group_seed from users.json.
	
	Returns:
		(users_list, group_seed_str_or_none)
	"""
	with open(path, "r", encoding="utf-8") as f:
		data = json.load(f)
	
	# Handle both flat list and nested {"users": [...]} formats
	if isinstance(data, list):
		users = data
		group_seed = None
	elif isinstance(data, dict):
		users = data.get("users", [])
		group_seed = data.get("group_seed")
		# Convert to string if needed
		if group_seed is not None:
			group_seed = str(group_seed)
	else:
		users = []
		group_seed = None
	
	return users, group_seed


def deterministic_percent(seed: str, key: str) -> int:
	h = hashlib.sha256((seed + "|" + key).encode("utf-8")).hexdigest()
	return int(h[:8], 16) % 100


def fetch_captcha_token(admin_url: str, group_seed: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
	try:
		resp = requests.get(f"{admin_url.rstrip('/')}/admin/get_captcha_token", params={"group_seed": group_seed}, timeout=timeout)
		resp.raise_for_status()
		return resp.json()
	except Exception:
		return None


def generate_totp(secret: str, skew_seconds: int = 0) -> str:
	if skew_seconds:
		offset = random.uniform(-skew_seconds, skew_seconds)
		ts = int(time.time() + offset)
		return pyotp.TOTP(secret).at(ts)
	return pyotp.TOTP(secret).now()


def simulate(users: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
	out: List[Dict[str, Any]] = []
	for u in users:
		if not isinstance(u, dict):
			continue
		
		username = u.get("username") or u.get("user") or u.get("email") or u.get("id")
		if not username:
			continue
		
		secret = u.get("totp_secret")
		# Generate a secret if missing
		if not secret:
			secret = pyotp.random_base32()
		
		entry: Dict[str, Any] = {"username": username, "totp_secret": secret}

		# Decide captcha requirement (deterministic if group_seed provided)
		captcha_required = False
		if args.group_seed and args.captcha_rate > 0:
			p = deterministic_percent(args.group_seed, str(username))
			captcha_required = p < int(args.captcha_rate)
		elif args.captcha_rate > 0:
			captcha_required = random.random() < (float(args.captcha_rate) / 100.0)

		if captcha_required:
			entry["captcha_required"] = True
			if args.admin_url and args.group_seed:
				token_obj = fetch_captcha_token(args.admin_url, args.group_seed)
				if token_obj is not None:
					entry["captcha_token"] = token_obj
		else:
			entry["captcha_required"] = False

		# Generate TOTP and optionally produce wrong codes based on fail_rate
		code = generate_totp(secret, args.skew)
		if args.fail_rate and random.random() < args.fail_rate:
			# produce a wrong code of same length
			code = ("%0{}d".format(len(code))) % (random.randint(0, 10 ** len(code) - 1))

		entry["totp_code"] = code
		out.append(entry)

	return out


def main(argv: Optional[List[str]] = None) -> int:
	parser = argparse.ArgumentParser(description="TOTP + CAPTCHA simulator")
	parser.add_argument("--users-file", default="src/users.json", help="Path to users.json")
	parser.add_argument("--skew", type=int, default=0, help="Max clock skew in seconds (applies +/- randomly)")
	parser.add_argument("--fail-rate", type=float, default=0.0, help="Probability (0-1) to emit a wrong code")
	parser.add_argument("--captcha-rate", type=float, default=0.0, help="Percentage (0-100) of users requiring captcha")
	parser.add_argument("--group-seed", type=str, default=None, help="Deterministic seed for captcha selection and admin token request")
	parser.add_argument("--admin-url", type=str, default=None, help="Admin base URL to fetch captcha token from (e.g. http://localhost:5000)")
	parser.add_argument("--json-lines", action="store_true", help="Output one JSON object per line")

	args = parser.parse_args(argv)

	try:
		users, file_group_seed = load_users(args.users_file)
	except Exception as e:
		print(f"Failed to load users file: {e}", file=sys.stderr)
		return 2

	# Use CLI group_seed if provided, otherwise fall back to file
	if args.group_seed is None and file_group_seed is not None:
		args.group_seed = file_group_seed

	out = simulate(users, args)

	if args.json_lines:
		for item in out:
			print(json.dumps(item, ensure_ascii=False))
	else:
		print(json.dumps(out, ensure_ascii=False, indent=2))

	return 0


if __name__ == "__main__":
	raise SystemExit(main())

