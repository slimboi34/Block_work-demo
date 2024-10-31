from rest_framework.views import APIView
from rest_framework.response import Response
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
        return {'balance': data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8}
    return {'error': 'Failed to fetch balance'}

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
    """Create a 2-way payment."""
    wallet = Wallet()
    wallet.private_key = sender_private_key

    druid = hashlib.sha256(f"{sender_address}{recipient_address}{tokens}{item_identifier}".encode()).hexdigest()
    payload = {
        'sender': sender_address,
        'recipient': recipient_address,
        'tokens': tokens,
        'item': item_identifier,
        'druid': druid,
        'signature': wallet.sign_message(druid)
    }
    response = requests.post("https://mock-blockchain.com/make-2way-payment", json=payload)
    return response.json()

def accept_2way_payment(druid, address):
    """Accept a 2-way payment."""
    payload = {
        'druid': druid,
        'address': address
    }
    response = requests.post("https://mock-blockchain.com/accept-2way-payment", json=payload)
    return response.json()

class GenerateKeypairView(APIView):
    def get(self, request):
        wallet = Wallet()
        keypair = wallet.generate_keypair()
        return Response(keypair)

class BalanceView(APIView):
    def get(self, request, address):
        balance = get_balance(address)
        return Response(balance)

class TokenPaymentView(APIView):
    def post(self, request):
        sender_private_key = request.data.get('sender_private_key')
        sender_address = request.data.get('sender_address')
        recipient_address = request.data.get('recipient_address')
        amount = request.data.get('amount')

        result = make_token_payment(sender_private_key, sender_address, recipient_address, amount)
        return Response(result)

class TwoWayPaymentView(APIView):
    def post(self, request):
        sender_private_key = request.data.get('sender_private_key')
        sender_address = request.data.get('sender_address')
        recipient_address = request.data.get('recipient_address')
        tokens = request.data.get('tokens')
        item_identifier = request.data.get('item_identifier')

        result = make_2way_payment(sender_private_key, sender_address, recipient_address, tokens, item_identifier)
        return Response(result)

class AcceptTwoWayPaymentView(APIView):
    def post(self, request):
        druid = request.data.get('druid')
        address = request.data.get('address')

        result = accept_2way_payment(druid, address)
        return Response(result)