from eth_account import Account
import secrets

def generate_eth_wallet():
    # Generate random 256-bit private key
    private_key = secrets.token_hex(32)

    # Create account from private key
    account = Account.from_key(private_key)

    return {
        "private_key": private_key,
        "public_key": account._key_obj.public_key.to_hex(),
        "wallet_address": account.address
    }

if __name__ == "__main__":
    wallet = generate_eth_wallet()
    print("Private Key:", wallet["private_key"])
    print("Public Key :", wallet["public_key"])
    print("Address    :", wallet["wallet_address"])
