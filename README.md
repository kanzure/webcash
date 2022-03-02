# Webcash

Webcash is an experimental new electronic cash ("e-cash") that enables decentralized and instant payments to anyone, anywhere in the world. Users send webcash to one another directly on a decentralized peer-to-peer basis by copying-and-pasting their webcash to their recipient. The central server helps webcash wallets detect double-spending and ensure the integrity of the monetary supply according to the supply schedule.

Navigate to <a href="https://webcash.org/">https://webcash.org/</a> for more information, including the Terms of Service.

## Installation

This is a python-based webcash client.

```
pip3 install -r requirements.txt
```

## Usage

```
python3 walletclient.py setup
python3 walletclient.py status
python3 miner.py
python3 walletclient.py pay 5
python3 walletclient.py pay 18.00 "memo: for lunch with bob"
python3 walletclient.py insert
```

## Mining

See <a href="https://github.com/maaku/webminer">webminer</a> for a substantially faster mining client.

## License

This repository and its source code is distributed under the BSD license.
