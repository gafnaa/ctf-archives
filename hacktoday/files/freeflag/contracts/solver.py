#!/usr/bin/env python3
import os
import sys
from foundpy import config, Contract
from web3 import Web3
from web3.exceptions import ContractLogicError

RPC_URL = "http://103.160.212.3:24376/df34546b-7af0-4c40-beca-ddc0a53d931f"
PRIVKEY = "0x54566ce3388dc604bc02536a0d9171b158f17d9388569862525f6080b9400e0a"
SETUP_CONTRACT_ADDR = "0x0ED0826d29B4907E36604fa14c070E97Bb7824E6"
SETUP_CONTRACT_FILE = "./Setup.sol"
WARMUP_CONTRACT_FILE = "./Warmup.sol"

A = 4242
B = 696969

def get_w3():
    w3 = getattr(config, "web3", None)
    if w3 is None:
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
    return w3

def main():
    config.setup(rpc_url=RPC_URL, privkey=PRIVKEY)

    w3 = get_w3()

    setup = Contract(addr=SETUP_CONTRACT_ADDR, file=SETUP_CONTRACT_FILE)

    warmup_addr = setup.contract.functions.warmup().call()
    print("Warmup at:", warmup_addr)

    try:
        before = setup.contract.functions.isSolved().call()
        print("isSolved (before):", before)
    except ContractLogicError as e:
        print("isSolved() call failed:", e, file=sys.stderr)

    warmup = Contract(addr=warmup_addr, file=WARMUP_CONTRACT_FILE)

    tx_hash = warmup.contract.functions.solve(A, B).transact()
    print("sent tx:", tx_hash.hex())

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print("mined block:", receipt.blockNumber, "status:", receipt.status)

    after = setup.contract.functions.isSolved().call()
    print("isSolved (after):", after)

    sys.exit(0 if after else 1)

if __name__ == "__main__":
    main()
