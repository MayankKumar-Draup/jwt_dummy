from django.urls import path
from .views import *

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('hello-class/', HelloView.as_view(), name='hello'),
    # path('v2/', HelloV2View.as_view(), name='hellov2'),
    path('hello1/', hello_view_1),
    path('hello2/', hello_view_2),
    path('dummy/', DummyView.as_view(), name='dummy'),
]
