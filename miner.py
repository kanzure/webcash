"""
Prototype of a miner.
"""

import os
import hashlib
import secrets
import datetime
import json
import base64
import requests
import time

from webcash import (
    SecretWebcash,
    compute_target,
)

from walletclient import (
    load_webcash_wallet,
    save_webcash_wallet,
    create_webcash_wallet,
)

INTERVAL_LENGTH_IN_SECONDS = 10

WALLET_FILENAME = "default_wallet.webcash"

def get_protocol_settings():
    response = requests.get("https://webcash.tech/api/v1/target")
    # difficulty_target_bits, ratio, mining_amount, mining_subsidy_amount
    return response.json()

def mine():
    """
    Use proof-of-work to mine for webcash in a loop.
    """
    protocol_settings = get_protocol_settings()

    last_difficulty_target_fetched_at = datetime.datetime(year=2020, month=1, day=1, hour=1, minute=0)

    if not os.path.exists(WALLET_FILENAME):
        webcash_wallet = create_webcash_wallet()
    else:
        webcash_wallet = load_webcash_wallet()

    while True:
        # every 10 seconds, get the latest difficulty
        fetch_frequency = INTERVAL_LENGTH_IN_SECONDS # seconds
        fetch_timedelta = datetime.datetime.now() - last_difficulty_target_fetched_at
        if fetch_timedelta > datetime.timedelta(seconds=fetch_frequency):
            last_difficulty_target_fetched_at = datetime.datetime.now()
            protocol_settings = get_protocol_settings()
            difficulty_target_bits = protocol_settings["difficulty_target_bits"]
            ratio = protocol_settings["ratio"]
            target = compute_target(difficulty_target_bits)
            print(f"server says difficulty={difficulty_target_bits} ratio={ratio}")

        mining_amount = protocol_settings["mining_amount"]
        mining_subsidy_amount = protocol_settings["mining_subsidy_amount"]
        mining_amount_remaining = mining_amount - mining_subsidy_amount

        keep_webcash = [
            str(SecretWebcash(mining_amount_remaining, secrets.token_hex(32))),
        ]

        subsidy_webcash = [
            str(SecretWebcash(mining_subsidy_amount, secrets.token_hex(32))),
        ]

        data = {
            "webcash": keep_webcash + subsidy_webcash,
            "subsidy": subsidy_webcash,
        }
        preimage = base64.b64encode(bytes(json.dumps(data), "ascii")).decode("ascii")
        work = int(hashlib.sha256(bytes(str(preimage), "ascii")).hexdigest(), 16)

        if work <= target:
            print(f"success! difficulty_target_bits={difficulty_target_bits} target={hex(target)} work={hex(work)}")

            mining_report = {
                "work": int(work),
                "preimage": str(preimage),
            }

            response = requests.post("https://webcash.tech/api/v1/mining_report", json=mining_report)
            print(f"submission response: {response.content}")
            if response.status_code != 200:
                last_difficulty_target_fetched_at = datetime.datetime.now() - datetime.timedelta(seconds=20)
                continue

            webcash = data["webcash"]
            webcash_wallet["webcash"].extend(keep_webcash)
            save_webcash_wallet(webcash_wallet)
            print(f"I have created {mining_amount} webcash... wallet saved!")
            #time.sleep(0.25)

if __name__ == "__main__":
    mine()
