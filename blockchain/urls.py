from django.urls import path
from .views import GenerateKeypairView, BalanceView, TokenPaymentView, TwoWayPaymentView, AcceptTwoWayPaymentView

urlpatterns = [
    path('wallet/generate-keypair/', GenerateKeypairView.as_view()),
    path('wallet/balance/<str:address>/', BalanceView.as_view()),
    path('wallet/make-payment/', TokenPaymentView.as_view()),
    path('wallet/make-2way-payment/', TwoWayPaymentView.as_view()),
    path('wallet/accept-2way-payment/', AcceptTwoWayPaymentView.as_view()),
]