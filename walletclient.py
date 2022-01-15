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
import datetime
import os
import sys

import requests
import click

#from miner import mine
from webcash import (
    SecretWebcash,
    PublicWebcash,
    LEGALESE,
    check_legal_agreements,
    deserialize_amount,
)

from utils import lock_wallet

# unused?
FEE_AMOUNT = 0

WALLET_NAME = "default_wallet.webcash"

# TODO: decryption
def load_webcash_wallet(filename=WALLET_NAME):
    webcash_wallet = json.loads(open(filename, "r").read())
    return webcash_wallet

# TODO: encryption
def save_webcash_wallet(webcash_wallet, filename=WALLET_NAME):
    with open(filename, "w") as fd:
        fd.write(json.dumps(webcash_wallet))
    return True

def create_webcash_wallet():
    return {
        "version": "1.0",
        "legalese": {disclosure_name: None for disclosure_name in LEGALESE.keys()},
        "log": [],
        "webcash": [],
    }

if not os.path.exists(WALLET_NAME):
    print(f"Didn't find an existing webcash wallet, making a new one called {WALLET_NAME}")
    webcash_wallet = create_webcash_wallet()
    with open(WALLET_NAME, "w") as fd:
        fd.write(json.dumps(webcash_wallet))

def get_info():
    webcash_wallet = load_webcash_wallet()

    amount = 0
    for webcash in webcash_wallet["webcash"]:
        webcash = SecretWebcash.deserialize(webcash)
        amount += webcash.amount

    print(f"Total amount stored in this wallet (if secure): e{amount}")

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

@cli.command("setup")
def setup():
    webcash_wallet = load_webcash_wallet()
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
    new_webcash = SecretWebcash(amount=webcash.amount, secret_value=secrets.token_hex(32))

    replace_request = {
        "webcashes": [str(webcash)],
        "new_webcashes": [str(new_webcash)],
        "legalese": webcash_wallet["legalese"],
    }
    #print("Sending to the server this replacement request: ", replace_request)

    response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)
    if response.status_code != 200:
        raise Exception("Something went wrong on the server: ", response.content)

    # save this one in the wallet
    webcash_wallet["webcash"].append(str(new_webcash))

    # preserve the memo
    webcash_wallet["log"].append({
        "type": "receive",
        "memo": str(memo),
        "amount": str(new_webcash.amount),
        "webcash": str(new_webcash),
    })

    print(f"Done! Saved e{new_webcash.amount} in the wallet, with the memo: {memo}")

    save_webcash_wallet(webcash_wallet)

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
        mychange = SecretWebcash(amount=change, secret_value=secrets.token_hex(32))
        payable = SecretWebcash(amount=amount, secret_value=secrets.token_hex(32))
        replace_request = {
            "webcashes": [str(ec) for ec in use_this_webcash],
            "new_webcashes": [str(mychange), str(payable)],
            "legalese": webcash_wallet["legalese"],
        }
        print("Sending to the server this replacement request: ", replace_request)
        response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)

        if response.status_code != 200:
            raise Exception("Something went wrong on the server: ", response.content)

        # remove old webcashes
        for ec in use_this_webcash:
            #new_wallet = [x for x in webcash_wallet["webcash"] if x != str(ec)]
            #webcash_wallet["webcash"] = new_wallet
            webcash_wallet["webcash"].remove(str(ec))

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
        payable = SecretWebcash(amount=amount, secret_value=secrets.token_hex(32))

        replace_request = {
            "webcashes": [str(ec) for ec in use_this_webcash],
            "new_webcashes": [str(payable)],
            "legalese": webcash_wallet["legalese"],
        }

        #print("replace_request: ", replace_request)

        print("Sending to the server this replacement request: ", replace_request)
        response = requests.post("https://webcash.tech/api/v1/replace", json=replace_request)

        if response.status_code != 200:
            raise Exception("Something went wrong on the server: ", response.content)

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
        "webcash": str(use_this_webcash[0]),
        "timestamp": str(datetime.datetime.now()),
    })

    print(f"Make this payment using the following webcash: {str(use_this_webcash[0])}")

    save_webcash_wallet(webcash_wallet)

if __name__ == "__main__":
    cli()
