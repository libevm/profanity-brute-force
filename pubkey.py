import argparse

import eth_keys
import hexbytes
from eth_account._utils import signing
from eth_account._utils.legacy_transactions import vrs_from


def get_public_key(tx_raw):
    txn_bytes = hexbytes.HexBytes(tx_raw)

    try:
        typed_txn = signing.TypedTransaction.from_bytes(txn_bytes)
        msg_hash = typed_txn.hash()
        vrs = typed_txn.vrs()

    except:
        txn = signing.Transaction.from_bytes(txn_bytes)
        msg_hash = signing.hash_of_signed_transaction(txn)
        vrs = vrs_from(txn)

    hash_bytes = hexbytes.HexBytes(msg_hash)

    v, r, s = vrs
    v_standard = signing.to_standard_v(v)
    vrs = (v_standard, r, s)

    signature_obj = eth_keys.KeyAPI().Signature(vrs=vrs)
    pubkey = signature_obj.recover_public_key_from_msg_hash(hash_bytes)

    return pubkey

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--transaction", type=str, help="Raw Tx Hex", required=True)
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    tx_raw = args.transaction
    pubkey = get_public_key(tx_raw)
    print(f"Pubkey: {pubkey}")
