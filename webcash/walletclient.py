#!/usr/bin/python3
"""
To install:

python3 -m venv venv/
source ./venv/bin/activate
pip3 install requests click

# do some mining
python3 miner.py

python3 walletclient.py status
python3 walletclient.py insert <webcash> <memo(optional)>
python3 walletclient.py pay 5.15 <memo(optional)>

That's it!
"""

import json
import decimal
import secrets
import hashlib
import datetime
import struct
import os
import sys

import requests
import click

#from miner import mine
from .webcashbase import (
    SecretWebcash,
    PublicWebcash,
    LEGALESE,
    check_legal_agreements,
    deserialize_amount,
)

from .utils import lock_wallet

# unused?
FEE_AMOUNT = 0

WALLET_NAME = "default_wallet.webcash"

CHAIN_CODES = {
    "RECEIVE": 0,
    "PAY": 1,
    "CHANGE": 2,
    "MINING": 3,
}

def convert_secret_hex_to_bytes(secret):
    """
    Convert a string secret to bytes.
    """
    return int(secret, 16).to_bytes(32, byteorder="big")

def generate_new_secret(webcash_wallet=None, chain_code="RECEIVE", walletdepth=None):
    """
    Derive a new secret using the deterministic wallet's master secret.
    """
    if webcash_wallet:
        walletdepth_param = walletdepth
        if walletdepth == None:
            walletdepth = webcash_wallet["walletdepths"][chain_code]
        else:
            walletdepth = walletdepth

        master_secret = webcash_wallet["master_secret"]
        master_secret_bytes = convert_secret_hex_to_bytes(master_secret)

        tag = hashlib.sha256(b"webcashwalletv1").digest()
        new_secret = hashlib.sha256(tag + tag)
        new_secret.update(master_secret_bytes)
        new_secret.update(struct.pack(">Q", CHAIN_CODES[chain_code.upper()])) # big-endian
        new_secret.update(struct.pack(">Q", walletdepth))
        new_secret = new_secret.hexdigest()

        # Record the change in walletdepth, but don't record the new secret
        # because (1) it can be re-constructed even if it is lost, and (2) the
        # assumption is that other code elsewhere will do something with the
        # new secret.
        if walletdepth_param == None:
            # Only update the walletdepth if the walletdepth was not provided.
            # This allows for the recovery function to work correctly.
            webcash_wallet["walletdepths"][chain_code] = (walletdepth + 1)

        save_webcash_wallet(webcash_wallet)
    else:
        raise NotImplementedError
    return new_secret

def generate_new_master_secret():
    """
    Generate a new random master secret for the deterministic wallet.
    """
    return secrets.token_hex(32)

def generate_initial_walletdepths():
    """
    Setup the walletdepths object all zeroed out for each of the chaincodes.
    """
    return {key.upper(): 0 for key in CHAIN_CODES.keys()}

# TODO: decryption
def load_webcash_wallet(filename=WALLET_NAME):
    webcash_wallet = json.loads(open(filename, "r").read())

    if "unconfirmed" not in webcash_wallet:
        webcash_wallet["unconfirmed"] = []

    if "walletdepths" not in webcash_wallet:
        webcash_wallet["walletdepths"] = generate_initial_walletdepths()
        save_webcash_wallet(webcash_wallet)

    if "master_secret" not in webcash_wallet:
        print("Generating a new master secret for the wallet (none previously detected)")

        webcash_wallet["master_secret"] = generate_new_master_secret()
        save_webcash_wallet(webcash_wallet)

        print("Be sure to backup your wallet for safekeeping of its master secret.")

    return webcash_wallet

# TODO: encryption
def save_webcash_wallet(webcash_wallet, filename=WALLET_NAME):
    with open(filename, "w") as fd:
        fd.write(json.dumps(webcash_wallet))
    return True

def create_webcash_wallet():
    print("Generating a new wallet with a new master secret...")
    master_secret = generate_new_master_secret()

    return {
        "version": "1.0",
        "legalese": {disclosure_name: None for disclosure_name in LEGALESE.keys()},
        "log": [],
        "webcash": [],
        "unconfirmed": [],

        # The deterministic wallet uses the master secret to generate new
        # secrets in a recoverable way. As long as the master secret is backed
        # up, it's possible to recover webcash in the event of a loss of the
        # wallet file.
        "master_secret": master_secret,

        # walletdepths has multiple counters to track how many secrets have
        # been generated so that the wallet can generate unique secrets. Each
        # chaincode is used for a different purpose, like RECEIVE, CHANGE, and
        # PAY.
        "walletdepths": generate_initial_walletdepths(),
    }

def get_info():
    webcash_wallet = load_webcash_wallet()

    amount = 0
    for webcash in webcash_wallet["webcash"]:
        webcash = SecretWebcash.deserialize(webcash)
        amount += webcash.amount

    print(f"Total amount stored in this wallet (if secure): e{amount}")

    walletdepths = webcash_wallet["walletdepths"]
    print(f"walletdepth: {walletdepths}")

@click.group()
def cli():
    pass

@cli.command("info")
def info():
    return get_info()

@cli.command("status")
def status():
    return get_info()

def yes_or_no(question):
    while "the user failed to choose y or n":
        reply = str(input(question+' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return False

def ask_user_for_legal_agreements(webcash_wallet):
    """
    Allow the user to agree to the agreements, disclosures, and
    acknowledgements.
    """
    acks = check_legal_agreements(webcash_wallet)
    if acks:
        print("User has already agreed and acknowledged the disclosures.")
    elif not acks:
        for (disclosure_name, disclosure) in LEGALESE.items():
            print(f"Disclosure \"{disclosure_name}\": {disclosure}")
            print("\n\n")
            answer = yes_or_no(f"Do you agree?")

            if answer == False:
                print(f"Unfortunately, you must acknowledge and agree to all agreements to use webcash.")
                sys.exit(0)
            elif answer == True:
                webcash_wallet["legalese"][disclosure_name] = True
                continue

        print("\n\n\nAll done! You've acknowledged all the disclosures. You may now use webcash.")

        save_webcash_wallet(webcash_wallet)

@cli.command("setup")
def setup():
    webcash_wallet = load_webcash_wallet()
    ask_user_for_legal_agreements(webcash_wallet)

def check_wallet():
    webcash_wallet = load_webcash_wallet()

    outputs = {}
    for webcash in webcash_wallet["webcash"]:
        sk = SecretWebcash.deserialize(webcash)
        if str(sk.to_public().hashed_value) in outputs.keys():
            print("Duplicate webcash detected in wallet, moving it to unconfirmed")
            webcash_wallet["unconfirmed"].append(webcash)
            webcash_wallet["webcash"].remove(webcash)
        outputs[str(sk.to_public().hashed_value)] = webcash

    while outputs:
        # Batch into no more than 25 at a time
        batch = {}
        while outputs and len(batch) < 25:
            item = outputs.popitem()
            batch[item[0]] = item[1]

        print(f"Checking batch of {len(batch)} public webcash")
        health_check_request = [str(x) for x in batch.values()]
        response = requests.post("https://webcash.tech/api/v1/health_check", json=health_check_request)
        if response.status_code != 200:
            raise Exception("Something went wrong on the server: ", response.content)
        response = json.loads(response.content)
        if response.get("status", "") != "success":
            raise Exception("Something went wrong on the server: ", json.dumps(response))

        for webcash, result in response["results"].items():
            if result["spent"] in (None, True):
                print(f"Invalid webcash found: {str(webcash)}; removing from wallet")

                # Use this as the key so that amount differences don't cause an
                # item-not-found error on otherwise same webcash.
                webcash_hashed_value = PublicWebcash.deserialize(webcash).hashed_value

                if webcash_hashed_value not in batch:
                    raise Exception(f"Server-returned webcash {str(webcash)} wasn't in our request.  This should never happen!")

                webcash_wallet["unconfirmed"].append(batch[webcash_hashed_value])
                webcash_wallet["webcash"].remove(batch[webcash_hashed_value])
            elif result["spent"] == False:
                # check the amount...
                webcash_hashed_value = PublicWebcash.deserialize(webcash).hashed_value
                wallet_cash = SecretWebcash.deserialize(batch[webcash_hashed_value])
                result_amount = decimal.Decimal(result["amount"])
                if result_amount != wallet_cash.amount:
                    print(f"Wallet mistakenly thought it had a webcash with amount {wallet_cash.amount} but instead the webcash was for amount {result_amount}; fixing..")
                    webcash_wallet["webcash"].remove(batch[webcash_hashed_value])
                    webcash_wallet["webcash"].append("e" + str(result_amount) + ":secret:" + wallet_cash.secret_value)

    save_webcash_wallet(webcash_wallet)

@cli.command("check")
@lock_wallet
def check():
    return check_wallet()

@cli.command("recover")
@click.option("--gaplimit", default=20)
@lock_wallet
def recover(gaplimit):
    """
    Recover webcash from a webcash wallet using its master secret as a
    deterministic seed. Also check all webcash in the wallet.
    """
    # gaplimit is the maximum window span that will be used, on the assumption
    # that any valid webcash will be found within the last item plus gaplimit
    # number more of the secrets.
    gaplimit = int(gaplimit)

    # Check all the webcash in the wallet and remove any webcash that has been
    # already spent.
    check_wallet()

    # check_wallet will save the wallet, so load it again
    webcash_wallet = load_webcash_wallet()

    for chain_code in webcash_wallet["walletdepths"].keys():
        # keep track of where we're at in this process
        current_walletdepth = 0

        reported_walletdepth = webcash_wallet["walletdepths"][chain_code]

        # Iterate through gaplimit-many secrets at a time and check each one.
        _idx = 0
        last_used_walletdepth = 0
        has_had_webcash = True
        while has_had_webcash:
            print(f"Checking gaplimit {gaplimit} secrets for chaincode {chain_code}, round {_idx}...")

            # assume this is the last iteration
            has_had_webcash = False

            # Check the next gaplimit number of secrets. Continue to the next round
            # if any of the secrets have ever been used, regardless of whether they
            # still have value.

            check_webcashes = {}
            for x in range(current_walletdepth, current_walletdepth + gaplimit):
                secret = generate_new_secret(webcash_wallet, chain_code=chain_code, walletdepth=x)
                webcash = SecretWebcash.deserialize("e1:secret:" + secret)
                check_webcashes[webcash.to_public().hashed_value] = webcash
                webcash.walletdepth = x

            health_check_request = [str(swc.to_public()) for (pwc, swc) in check_webcashes.items()]
            response = requests.post("https://webcash.tech/api/v1/health_check", json=health_check_request)
            if response.status_code != 200:
                raise Exception("Something went wrong on the server: ", response.content)
            response = json.loads(response.content)
            if response.get("status", "") != "success":
                raise Exception("Something went wrong on the server: ", json.dumps(response))

            #idx = 0
            for (public_webcash, result) in response["results"].items():
                public_webcash = PublicWebcash.deserialize(public_webcash).hashed_value

                if result["spent"] != None:
                    has_had_webcash = True
                    #last_used_walletdepth = current_walletdepth + idx
                    last_used_walletdepth = check_webcashes[public_webcash].walletdepth

                if result["spent"] == False:
                    wc = check_webcashes[public_webcash]
                    wc.amount = decimal.Decimal(result["amount"])
                    if chain_code.upper() != "PAY" and str(wc) not in webcash_wallet["webcash"]:
                        print(f"Recovered webcash: {wc.amount}")
                        webcash_wallet["webcash"].append(str(check_webcashes[public_webcash]))
                    else:
                        print(f"Found known webcash of amount: {wc.amount} (might be a payment)")

                #idx += 1

            # continue anyway if the wallet says its walletdepth is greater
            #if max([wc.walletdepth for wc in check_webcashes.values()]) < reported_walletdepth:
            if current_walletdepth < reported_walletdepth:
                has_had_webcash = True

            if has_had_webcash:
                current_walletdepth = current_walletdepth + gaplimit

            _idx += 1

        if reported_walletdepth > last_used_walletdepth + 1:
            print(f"Something may have gone wrong: reported walletdepth was {reported_walletdepth} but only found up to {last_used_walletdepth} depth")

        if reported_walletdepth < last_used_walletdepth:
            webcash_wallet["walletdepths"][chain_code] = last_used_walletdepth + 1

    # TODO: only save the wallet when it has been modified?
    print("Saving wallet...")
    save_webcash_wallet(webcash_wallet)

@cli.command("insert")
@click.argument("webcash")
@click.argument("memo", nargs=-1)
@lock_wallet
def insert(webcash, memo=""):
    if type(memo) == list or type(memo) == tuple:
        memo = " ".join(memo)

    webcash_wallet = load_webcash_wallet()

    acks = check_legal_agreements(webcash_wallet)
    if not acks:
        print("User must acknowledge and agree to agreements first.")
        return

    # make sure it's valid webcash
    webcash = SecretWebcash.deserialize(webcash)

    # store it in a new webcash
    new_webcash = SecretWebcash(amount=webcash.amount, secret_value=generate_new_secret(webcash_wallet, chain_code="RECEIVE"))

    replace_request = {
        "webcashes": [str(webcash)],
        "new_webcashes": [str(new_webcash)],
        "legalese": webcash_wallet["legalese"],
    }
    # Save the webcash to the wallet in case there is a network error while
    # attempting to replace it.
    unconfirmed_webcash = [str(webcash), str(new_webcash)]
    webcash_wallet["unconfirmed"].extend(unconfirmed_webcash)
    save_webcash_wallet(webcash_wallet)
    #print("Sending to the server this replacement request: ", replace_request)

    response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)
    if response.status_code != 200:
        raise Exception("Something went wrong on the server: ", response.content)

    # save this one in the wallet
    webcash_wallet["webcash"].append(str(new_webcash))

    # remove "unconfirmed" webcash
    for wc in unconfirmed_webcash:
        webcash_wallet["unconfirmed"].remove(wc)

    # preserve the memo
    webcash_wallet["log"].append({
        "type": "receive",
        "memo": str(memo),
        "amount": str(new_webcash.amount),
        "input_webcash": str(webcash),
        "output_webcash": str(new_webcash),
    })

    save_webcash_wallet(webcash_wallet)
    print(f"Done! Saved e{new_webcash.amount} in the wallet, with the memo: {memo}")

@cli.command("insertmany")
@click.argument("webcash", nargs=-1)
@lock_wallet
def insertmany(webcash):
    """
    Insert multiple webcash into the wallet at the same time. Each webcash gets
    merged together in a single request. Use whitespace to separate each
    webcash on the command line.
    """

    # TODO: consolidate common functionality duplicated with "insert"

    webcash_wallet = load_webcash_wallet()

    # TODO: move this into a shared decorator
    acks = check_legal_agreements(webcash_wallet)
    if not acks:
        print("User must acknowledge and agree to agreements first.")
        return

    # use set to filter out duplicates by total string value
    webcashes = list(set(webcash))

    # deserialize
    webcashes = [SecretWebcash.deserialize(wc) for wc in webcash]

    # further filter out duplicates by secret_value
    wc_secrets = [wc.secret_value for wc in webcashes]
    deduped = list(set([(wc_secrets.count(wc.secret_value), str(wc)) for wc in webcashes]))
    webcashes = [SecretWebcash.deserialize(x[1]) for x in deduped]

    total_amount = sum([wc.amount for wc in webcashes])

    merged_webcash_secret = generate_new_secret(webcash_wallet, chain_code="RECEIVE")
    merged_webcash = SecretWebcash(amount=decimal.Decimal(total_amount), secret_value=merged_webcash_secret)

    replace_request = {
        "webcashes": [str(wc) for wc in webcashes],
        "new_webcashes": [str(merged_webcash)],
        "legalese": webcash_wallet["legalese"],
    }

    unconfirmed_webcashes = [str(wc) for wc in webcashes] + [str(merged_webcash)]
    webcash_wallet["unconfirmed"].extend(unconfirmed_webcashes)
    save_webcash_wallet(webcash_wallet)

    response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)
    if response.status_code != 200:
        raise Exception("Something went wrong on the server: ", response.content)

    webcash_wallet["webcash"].append(str(merged_webcash))

    # remove "unconfirmed" webcash
    for wc in unconfirmed_webcashes:
        webcash_wallet["unconfirmed"].remove(wc)

    webcash_wallet["log"].append({
        "type": "receive",
        "memo": "",
        "amount": str(merged_webcash.amount),
        "input_webcash": [str(wc) for wc in webcashes],
        "output_webcash": [str(merged_webcash)],
    })

    save_webcash_wallet(webcash_wallet)
    print(f"Done! Saved e{merged_webcash.amount} in the wallet.")

@cli.command("pay")
@click.argument('amount')
@click.argument('memo', nargs=-1)
@lock_wallet
def pay(amount, memo=""):
    amount = deserialize_amount(str(amount))
    int(amount) # just to make sure
    amount += FEE_AMOUNT # fee...
    webcash_wallet = load_webcash_wallet()

    acks = check_legal_agreements(webcash_wallet)
    if not acks:
        print("User must acknowledge and agree to all agreements first.")
        return

    # scan for an amount
    use_this_webcash = []
    for webcash in webcash_wallet["webcash"]:
        webcash = SecretWebcash.deserialize(webcash)

        if webcash.amount >= amount:
            use_this_webcash.append(webcash)
            break
    else:
        running_amount = decimal.Decimal(0)
        running_webcash = []
        for webcash in webcash_wallet["webcash"]:
            webcash = SecretWebcash.deserialize(webcash)
            running_webcash.append(webcash)
            running_amount += webcash.amount

            if running_amount >= amount:
                use_this_webcash = running_webcash
                break
        else:
            print("Couldn't find enough webcash in the wallet.")
            sys.exit(0)

    found_amount = sum([ec.amount for ec in use_this_webcash])
    print(f"found_amount: {found_amount}")
    if found_amount > (amount + FEE_AMOUNT): # +1 for the fee
        change = found_amount - amount - FEE_AMOUNT
        print(f"change: {change}")

        mychange = SecretWebcash(amount=change, secret_value=generate_new_secret(webcash_wallet, chain_code="CHANGE"))
        payable = SecretWebcash(amount=amount, secret_value=generate_new_secret(webcash_wallet, chain_code="PAY"))

        replace_request = {
            "webcashes": [str(ec) for ec in use_this_webcash],
            "new_webcashes": [str(mychange), str(payable)],
            "legalese": webcash_wallet["legalese"],
        }

        # Save the webcash to the wallet in case there is a network error while
        # attempting to replace it.
        unconfirmed_webcash = [str(mychange), str(payable)]
        webcash_wallet["unconfirmed"].extend(unconfirmed_webcash)
        save_webcash_wallet(webcash_wallet)

        # Attempt replacement
        #print("Sending to the server this replacement request: ", replace_request)
        response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)

        if response.status_code != 200:
            raise Exception("Something went wrong on the server: ", response.content)

        # remove old webcashes
        for ec in use_this_webcash:
            #new_wallet = [x for x in webcash_wallet["webcash"] if x != str(ec)]
            #webcash_wallet["webcash"] = new_wallet
            webcash_wallet["webcash"].remove(str(ec))

        # remove unconfirmed webcashes
        for wc in unconfirmed_webcash:
            webcash_wallet["unconfirmed"].remove(wc)

        # store change
        webcash_wallet["webcash"].append(str(mychange))

        log_entry = {
            "type": "change",
            "amount": str(mychange.amount),
            "webcash": str(mychange),
            "timestamp": str(datetime.datetime.now()),
        }
        webcash_wallet["log"].append(log_entry)

        use_this_webcash = [payable]
    elif found_amount == amount + FEE_AMOUNT:
        payable = SecretWebcash(amount=amount, secret_value=generate_new_secret(webcash_wallet, chain_code="PAY"))

        replace_request = {
            "webcashes": [str(ec) for ec in use_this_webcash],
            "new_webcashes": [str(payable)],
            "legalese": webcash_wallet["legalese"],
        }
        # Save the webcash to the wallet in case there is a network error while
        # attempting to replace it.
        unconfirmed_webcash = [str(payable)]
        webcash_wallet["unconfirmed"].extend(unconfirmed_webcash)
        save_webcash_wallet(webcash_wallet)

        #print("replace_request: ", replace_request)

        #print("Sending to the server this replacement request: ", replace_request)
        response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)

        if response.status_code != 200:
            raise Exception("Something went wrong on the server: ", response.content)

        # remove unconfirmed webcashes
        for wc in unconfirmed_webcash:
            webcash_wallet["unconfirmed"].remove(wc)

        # remove old webcashes
        for ec in use_this_webcash:
            #new_wallet = [x for x in webcash_wallet["webcash"] if x != str(ec)]
            #webcash_wallet["webcash"] = new_wallet
            webcash_wallet["webcash"].remove(str(ec))

        use_this_webcash = [payable]
    else:
        raise NotImplementedError

    # store a record of this transaction
    webcash_wallet["log"].append({
        "type": "payment",
        "memo": " ".join(memo),
        "amount": str(amount),
        "input_webcashes": [str(ec) for ec in use_this_webcash],
        "output_webcash": str(payable),
        "timestamp": str(datetime.datetime.now()),
    })

    print(f"Make this payment using the following webcash: {str(use_this_webcash[0])}")

    save_webcash_wallet(webcash_wallet)

def main():
    # Create a new webcash wallet if one does not already exist.
    if not os.path.exists(WALLET_NAME):
        print(f"Didn't find an existing webcash wallet, making a new one called {WALLET_NAME}")
        webcash_wallet = create_webcash_wallet()
        ask_user_for_legal_agreements(webcash_wallet)
        save_webcash_wallet(webcash_wallet)

    return cli()

if __name__ == "__main__":
    main()
