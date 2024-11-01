from django.urls import path
from .views import (
    GenerateKeypairView,
    BalanceView,
    TokenPaymentView,
    TwoWayPaymentView,
    AcceptTwoWayPaymentView,
    BitcoinAddressGeneratorView,
    PeerToPeerTransferView,
    CheckBalanceView
)

urlpatterns = [
    path('wallet/generate-keypair/', GenerateKeypairView.as_view()),
    path('wallet/balance/<str:address>/', BalanceView.as_view()),
    path('wallet/make-payment/', TokenPaymentView.as_view()),
    path('wallet/make-2way-payment/', TwoWayPaymentView.as_view()),
    path('wallet/accept-2way-payment/', AcceptTwoWayPaymentView.as_view()),
    path('wallet/generate-bitcoin-address/', BitcoinAddressGeneratorView.as_view()),  # Bitcoin address generation
    path('wallet/peer-to-peer-transfer/', PeerToPeerTransferView.as_view()),  # New endpoint for peer-to-peer transfer
    path('wallet/check-balance/', CheckBalanceView.as_view()),  # New endpoint for checking balance
]