"""
Prototype of a miner.
"""

import base64
import datetime
import hashlib
import json
import os
import sys
from decimal import Decimal

from webcash.utils import lock_wallet
from webcash.walletclient import (
    create_webcash_wallet,
    generate_new_secret,
    load_webcash_wallet,
    save_webcash_wallet,
    webcash_server_request_raw,
)
from webcash.webcashbase import (
    WEBCASH_ENDPOINT_MINING_REPORT,
    WEBCASH_ENDPOINT_REPLACE,
    WEBCASH_ENDPOINT_TARGET,
    SecretWebcash,
    compute_target,
)

INTERVAL_LENGTH_IN_SECONDS = 10

WALLET_FILENAME = "default_wallet.webcash"


def get_protocol_settings():
    response = webcash_server_request_raw(WEBCASH_ENDPOINT_TARGET)
    # difficulty_target_bits, ratio, mining_amount, mining_subsidy_amount
    return response.json()


@lock_wallet
def mine():
    """
    Use proof-of-work to mine for webcash in a loop.
    """
    protocol_settings = get_protocol_settings()

    last_difficulty_target_fetched_at = datetime.datetime(
        year=2020, month=1, day=1, hour=1, minute=0
    )

    if not os.path.exists(WALLET_FILENAME):
        webcash_wallet = create_webcash_wallet()
    else:
        webcash_wallet = load_webcash_wallet()

    if webcash_wallet["legalese"]["terms"] is not True:
        print("Error: run walletclient.py setup first")
        sys.exit(1)

    attempts = 0

    keep = generate_new_secret(
        webcash_wallet,
        chain_code="MINING",
        walletdepth=webcash_wallet["walletdepths"]["MINING"] + 0,
    )
    subsidy = generate_new_secret(
        webcash_wallet,
        chain_code="PAY",
        walletdepth=webcash_wallet["walletdepths"]["PAY"] + 0,
    )

    while True:
        # every 10 seconds, get the latest difficulty
        fetch_frequency = INTERVAL_LENGTH_IN_SECONDS  # seconds
        fetch_timedelta = datetime.datetime.now() - last_difficulty_target_fetched_at
        if fetch_timedelta > datetime.timedelta(seconds=fetch_frequency):
            last_difficulty_target_fetched_at = datetime.datetime.now()
            protocol_settings = get_protocol_settings()
            difficulty_target_bits = protocol_settings["difficulty_target_bits"]
            ratio = protocol_settings["ratio"]
            target = compute_target(difficulty_target_bits)
            speed = attempts // fetch_timedelta.total_seconds() / 1000
            attempts = 0
            print(
                f"server says difficulty={difficulty_target_bits} ratio={ratio} speed={speed}khps"
            )

        mining_amount = Decimal(protocol_settings["mining_amount"])
        mining_subsidy_amount = Decimal(protocol_settings["mining_subsidy_amount"])
        mining_amount_remaining = mining_amount - mining_subsidy_amount

        keep_webcash = [
            str(SecretWebcash(mining_amount_remaining, keep)),
        ]

        subsidy_webcash = [
            str(SecretWebcash(mining_subsidy_amount, subsidy)),
        ]

        data = {
            "webcash": keep_webcash + subsidy_webcash,
            "subsidy": subsidy_webcash,
            "nonce": attempts,
            "timestamp": datetime.datetime.utcnow().timestamp(),
            "difficulty": int(difficulty_target_bits),
            "legalese": webcash_wallet["legalese"],
        }
        preimage = base64.b64encode(bytes(json.dumps(data), "ascii")).decode("ascii")
        work = int(hashlib.sha256(bytes(str(preimage), "ascii")).hexdigest(), 16)
        attempts += 1

        if work <= target:
            print(
                f"success! difficulty_target_bits={difficulty_target_bits} target={hex(target)} work={hex(work)}"
            )

            mining_report = {
                "work": int(work),
                "preimage": str(preimage),
                "legalese": webcash_wallet["legalese"],
            }

            keep = generate_new_secret(webcash_wallet, chain_code="MINING")
            subsidy = generate_new_secret(webcash_wallet, chain_code="PAY")

            response = webcash_server_request_raw(
                WEBCASH_ENDPOINT_MINING_REPORT, mining_report
            )
            print(f"submission response: {response.content}")
            if response.status_code != 200:
                # difficulty may have changed against us
                last_difficulty_target_fetched_at = (
                    datetime.datetime.now() - datetime.timedelta(seconds=20)
                )
                continue

            # Move the webcash to a new secret so that webcash isn't lost if
            # mining reports are one day public. At the same time,
            # consolidate the webcash wallet if possible to reduce wallet size.

            # Disable mining consolidation for now; you're welcome to test it
            # out.
            # if len(webcash_wallet["webcash"]) >= 6:
            if False:
                # pick some webcash for consolidation
                previous_webcashes = webcash_wallet["webcash"][-5:]
                previous_webcashes = [
                    SecretWebcash.deserialize(wc) for wc in previous_webcashes
                ]
                previous_amount = sum([pwc.amount for pwc in previous_webcashes])
                previous_webcashes = [str(wc) for wc in previous_webcashes]
            else:
                previous_webcashes = []
                previous_amount = 0

            print(f"I have created {mining_amount} webcash. Securing secret.")
            # Use the CHANGE chaincode because the original mined webcash was
            # already recorded in MINING. Everything in MINING that is unspent
            # needs to be replaced, and replacing already-replaced webcash is
            # redundant, so it should go into CHANGE instead.
            new_secret_value = generate_new_secret(webcash_wallet, chain_code="CHANGE")
            new_webcash = SecretWebcash(
                amount=mining_amount_remaining + previous_amount,
                secret_value=new_secret_value,
            )
            replace_request = {
                "webcashes": keep_webcash + previous_webcashes,
                "new_webcashes": [str(new_webcash)],
                "legalese": webcash_wallet["legalese"],
            }
            # Save the webcash to the wallet in case there is a network error
            # while attempting to replace it.
            unconfirmed_webcash = keep_webcash + [str(new_webcash)]
            webcash_wallet["unconfirmed"].extend(unconfirmed_webcash)
            save_webcash_wallet(webcash_wallet)
            # Attempt replacement (should not fail!)
            replace_response = webcash_server_request_raw(
                WEBCASH_ENDPOINT_REPLACE, replace_request
            )
            if replace_response.status_code != 200:
                # might happen if difficulty changed against us during mining
                # in which case we shouldn't get this far
                print("mining data was: " + str(data))
                print("mining response was: " + response.content.decode("ascii"))
                print("webcashes: " + str(keep_webcash))
                print("new_webcashes: " + str(new_webcash))
                raise Exception(
                    "Something went wrong when trying to secure the new webcash."
                )
            else:

                # remove old webcashes
                for wc in previous_webcashes:
                    webcash_wallet["webcash"].remove(str(wc))

                # remove "unconfirmed" webcash
                for wc in unconfirmed_webcash:
                    webcash_wallet["unconfirmed"].remove(wc)

                # save new webcash
                # webcash = data["webcash"]
                webcash_wallet["webcash"].extend([str(new_webcash)])
                save_webcash_wallet(webcash_wallet)
                print("Wallet saved!")
                # time.sleep(0.25)

            keep = generate_new_secret(
                webcash_wallet,
                chain_code="MINING",
                walletdepth=webcash_wallet["walletdepths"]["MINING"] + 0,
            )
            subsidy = generate_new_secret(
                webcash_wallet,
                chain_code="PAY",
                walletdepth=webcash_wallet["walletdepths"]["PAY"] + 0,
            )


if __name__ == "__main__":
    mine()
