#!/usr/bin/env python3
"""Validate services.json and probe every configured service once.

Config errors (missing/invalid file) exit 1; unreachable services are
reported as DOWN but do not fail the run — that is the thing this page
exists to show.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as monitor_app  # noqa: E402

services = monitor_app._load_services_config()
if not services:
    print('No usable services found in services.json')
    sys.exit(1)
print(f'{len(services)} service(s) configured · target host: {monitor_app.TARGET_HOST}')
cards = monitor_app.system_status()
down = 0
for card in cards:
    detail = str(card.get('detail') or card.get('loaded_model') or '').splitlines()
    print(f"{'OK  ' if card.get('ok') else 'DOWN'}  {card.get('name')}: {(detail[0] if detail else '')[:70]}")
    down += 0 if card.get('ok') else 1
print(f'\n{down} service(s) unreachable.')
