import os
import ecdsa
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import requests

class Wallet:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """Generate a new keypair."""
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        self.private_key = private_key.to_string().hex()
        self.public_key = public_key.to_string().hex()
        return {
            'private_key': self.private_key,
            'public_key': self.public_key
        }

    def sign_message(self, message):
        """Sign a message with the private key."""
        if not self.private_key:
            raise ValueError("Private key is not generated or set.")
        
        private_key = ecdsa.SigningKey.from_string(
            bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
        signature = private_key.sign(message.encode())
        return base64.b64encode(signature).decode()

    def verify_signature(self, message, signature, public_key):
        """Verify a signature."""
        public_key_obj = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        try:
            return public_key_obj.verify(base64.b64decode(signature), message.encode())
        except ecdsa.BadSignatureError:
            return False

def get_balance(address):
    """Fetch balance for a given Bitcoin testnet address."""
    response = requests.get(f"https://blockstream.info/testnet/api/address/{address}")
    if response.status_code == 200:
        data = response.json()
        # Convert the balance from satoshis to BTC for display
        return {'balance': data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8}
    return {'error': 'Failed to fetch balance'}

def send_testnet_coins(sender_private_key, sender_address, amount):
    """Send testnet BTC back to the designated address to contribute to the testnet ecosystem."""
    recipient_address = "tb1qlj64u6fqutr0xue85kl55fx0gt4m4urun25p7q"
    
    wallet = Wallet()
    wallet.private_key = sender_private_key

def make_token_payment(sender_private_key, sender_address, recipient_address, amount):
    """Make a token payment."""
    wallet = Wallet()
    wallet.private_key = sender_private_key

    payload = {
        'sender': sender_address,
        'recipient': recipient_address,
        'amount': amount,
        'signature': wallet.sign_message(f"{sender_address}{recipient_address}{amount}")
    }
    response = requests.post("https://mock-blockchain.com/make-payment", json=payload)
    return response.json()

def make_2way_payment(sender_private_key, sender_address, recipient_address, tokens, item_identifier):
    """Create a 2-way payment where both parties exchange assets."""
    wallet = Wallet()
    wallet.private_key = sender_private_key

    # Construct payload for 2-way transaction
    druid = hashlib.sha256(f"{sender_address}{recipient_address}{tokens}{item_identifier}".encode()).hexdigest()
    payload = {
        'sender': sender_address,
        'recipient': recipient_address,
        'tokens': tokens,
        'item': item_identifier,
        'druid': druid,
        'signature': wallet.sign_message(druid)
    }

    # Mock call to blockchain endpoint for 2-way payment
    response = requests.post("https://mock-blockchain.com/make-2way-payment", json=payload)
    return response.json()

def fetch_pending_2way_payments(address):
    """Fetch pending 2-way transactions for a given address."""
    response = requests.get(f"https://mock-blockchain.com/get-pending-2way-payments/{address}")
    return response.json() if response.status_code == 200 else {'error': 'Failed to fetch pending payments'}

def accept_2way_payment(druid, address):
    """Accept a 2-way payment."""
    payload = {
        'druid': druid,
        'address': address
    }
    response = requests.post("https://mock-blockchain.com/accept-2way-payment", json=payload)
    return response.json()

# Example testnet BTC address for demonstration purposes
btc_testnet_address = "tb1qlj64u6fqutr0xue85kl55fx0gt4m4urun25p7q"

# Example function call to get the balance of the testnet address
print(get_balance(btc_testnet_address))