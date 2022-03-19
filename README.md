# Webcash

Webcash is an experimental new electronic cash ("e-cash") that enables decentralized and instant payments to anyone, anywhere in the world. Users send webcash to one another directly on a decentralized peer-to-peer basis by copying-and-pasting their webcash to their recipient. The central server helps webcash wallets detect double-spending and ensure the integrity of the monetary supply according to the supply schedule.

Navigate to <a href="https://webcash.org/">https://webcash.org/</a> for more information, including the Terms of Service.

## Installation

This is a python-based webcash wallet client. To install the latest version on the python package index, use this:

```
pip3 install webcash
```

Otherwise, install locally for testing or development purposes:

```
pip3 install -e .
```

## Usage

```
webcash setup
webcash status
webcash pay 5
webcash pay 18 "memo: for lunch with bob"
webcash insert <webcash goes here>
```

## Mining

See <a href="https://github.com/maaku/webminer">webminer</a> for a substantially faster mining client.

This repository contains the original reference implementation of the miner which is much slower:

```
python3 miner.py
```

## License

This repository and its source code is distributed under the BSD license.
