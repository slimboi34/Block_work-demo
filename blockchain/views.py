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

import os
import ecdsa
import hashlib
import base58
from rest_framework.views import APIView



class PeerToPeerTransferView(APIView):
    def post(self, request):
        sender_public_key = request.data.get('public_key')
        sender_address = request.data.get('bitcoin_address')
        recipient_address = request.data.get('recipient_address')
        amount = request.data.get('amount')

        if not all([sender_public_key, sender_address, recipient_address, amount]):
            return Response({'error': 'Missing required fields'}, status=400)

        payload = {
            'sender_public_key': sender_public_key,
            'sender_address': sender_address,
            'recipient_address': recipient_address,
            'amount': amount
        }
        # Simulate the transfer request to a mock blockchain
        response = requests.post("https://mock-blockchain.com/send-transaction", json=payload)
        
        if response.status_code == 200:
            return Response(response.json(), status=200)
        return Response({'error': 'Transaction failed'}, status=500)

class CheckBalanceView(APIView):
    def get(self, request):
        private_key = request.query_params.get('private_key')
        bitcoin_address = request.query_params.get('bitcoin_address')

        if not private_key or not bitcoin_address:
            return Response({'error': 'private_key and bitcoin_address are required'}, status=400)

        # Fetch balance from a public API (modify with a reliable API endpoint)
        response = requests.get(f"https://blockstream.info/testnet/api/address/{bitcoin_address}")
        if response.status_code == 200:
            data = response.json()
            balance = data.get('chain_stats', {}).get('funded_txo_sum', 0) / 1e8
            return Response({'balance': balance})
        return Response({'error': 'Failed to fetch balance'}, status=500)








def generate_private_key():
    return os.urandom(32)

def get_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return b'\x04' + vk.to_string()

def hash_public_key(public_key):
    sha256_result = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_result)
    return ripemd160.digest()

def generate_bitcoin_address(public_key_hash):
    # Prepend version byte (0x00 for mainnet)
    network_byte = b'\x00'
    payload = network_byte + public_key_hash

    # Calculate checksum
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address_bytes = payload + checksum

    # Convert to Base58
    return base58.b58encode(address_bytes).decode()

# Generate private key
private_key = generate_private_key()
print("Private Key:", private_key.hex())

# Derive public key
public_key = get_public_key(private_key)
print("Public Key:", public_key.hex())

# Generate hashed public key
public_key_hash = hash_public_key(public_key)

# Generate Bitcoin address
bitcoin_address = generate_bitcoin_address(public_key_hash)
print("Bitcoin Address:", bitcoin_address)





class BitcoinAddressGeneratorView(APIView):
    def get(self, request):
        """Generate and return a new Bitcoin address."""
        private_key = generate_private_key()
        public_key = get_public_key(private_key)
        public_key_hash = hash_public_key(public_key)
        bitcoin_address = generate_bitcoin_address(public_key_hash)

        return Response({
            'private_key': private_key.hex(),
            'public_key': public_key.hex(),
            'bitcoin_address': bitcoin_address
        })

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