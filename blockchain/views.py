from rest_framework.views import APIView
from rest_framework.response import Response
from .blockchain_utils import Wallet, get_balance, make_token_payment, make_2way_payment, fetch_pending_2way_payments, accept_2way_payment

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