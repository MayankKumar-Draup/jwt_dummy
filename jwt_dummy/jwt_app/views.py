import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework.authentication import BaseAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from .serializers import DummySerializer
from .token_helper import generate_token


class MyAuth(BaseAuthentication):
    def authenticate(self, request):
        print("I am in MyAuth class.")
        return True, True


class MyPerm(permissions.BasePermission):

    def has_permission(self, request, view):
        print("I am in MyPerm class.")
        return True


class TokenObtainPairView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        print('username',username)
        user = authenticate(username=username, password=password)
        if user is None:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
        access_payload = {'user_id': user.id}
        access_token = generate_token(access_payload, 15)
        refresh_payload = {'user_id': user.id}
        refresh_token = generate_token(refresh_payload, 2880, 'refresh')
        user.refresh_token = refresh_token
        user.save()
        response_data = {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        return Response(response_data, status=status.HTTP_200_OK)


class TokenRefreshView(APIView):
    def post(self, request):
        User = get_user_model()
        refresh_token = request.data.get('refresh')
        try:
            refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = refresh_payload['user_id']
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Refresh token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
        except (jwt.DecodeError, jwt.InvalidTokenError) as e:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)
        if refresh_token != user.refresh_token:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        access_payload = {'user_id': user.id}
        access_token = generate_token(access_payload, 15)
        response_data = {
            'access_token': access_token,
        }
        return Response(response_data, status=status.HTTP_200_OK)


class HelloView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = (MyAuth,)

    def get(self, request):
        content = {'message': 'Hello World!!!!!'}
        return Response(content)


@permission_classes((IsAuthenticated,))
def hello_view_1(request):
    if request.method == 'GET':
        content = {'message': 'Hello World hello1!!!!!'}
        return JsonResponse(content)




@api_view(['GET'])
@authentication_classes((MyAuth,))
@permission_classes((AllowAny,))
def hello_view_2(request):
    if request.method == 'GET':
        content = {'message': 'Hello World!!!!!'}
        return JsonResponse(content)


class DummyView(APIView):
    """
    This is a dummy DRF view that takes in a lot of parameters.

    Parameters:
    -----------
    required_param : str (required)
        A required string parameter.

    optional_param1 : int (optional)
        An optional integer parameter.

    optional_param2 : str (optional)
        An optional string parameter.

    list_param : list (optional)
        A list parameter.

    list_of_lists : list of list (optional)
        A list of lists parameter.

    dict_param : dict (optional)
        A dictionary parameter.

    dict_of_lists : dict of list (optional)
        A dictionary of lists parameter.

    dict_of_lists_of_dicts : dict of list of dict (optional)
        A dictionary of lists of dictionaries parameter.

    Returns:
    --------
    Returns a JSON response with the input parameters received.

    Example:
    --------
    Request body:
    {
        "required_param": "hello",
        "optional_param1": 123,
        "list_param": [1, 2, 3],
        "list_of_lists": [[1, 2], [3, 4]],
        "list_of_lists_list":[[[1,2,3],[1,2,3]]],
        "dict_param": {"key1": "value1", "key2": "value2"},
        "dict_of_lists": {"key1": [1, 2], "key2": [3, 4]},
        "dict_of_lists_of_dicts": {"key1": [{"nested_key1": "nested_value1"}]}
    }

    Response:
    {
        "required_param": "hello",
        "optional_param1": 123,
        "list_param": [1, 2, 3],
        "list_of_lists": [[1, 2], [3, 4]],
        "list_of_lists_list":[[[1,2,3],[1,2,3]]],
        "dict_param": {"key1": "value1", "key2": "value2"},
        "dict_of_lists": {"key1": [1, 2], "key2": [3, 4]},
        "dict_of_lists_of_dicts": {"key1": [{"nested_key1": "nested_value1"}]}
    }
    """
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = DummySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        required_param = request.data.get('required_param')
        optional_param1 = request.data.get('optional_param1')
        optional_param2 = request.data.get('optional_param2')
        list_param = request.data.get('list_param')
        list_of_lists = request.data.get('list_of_lists')
        list_of_lists_list = request.data.get('list_of_lists_list')
        dict_param = request.data.get('dict_param')
        dict_of_lists = request.data.get('dict_of_lists')
        dict_of_lists_of_dicts = request.data.get('dict_of_lists_of_dicts')

        # Perform some dummy processing
        result = {
            "required_param": required_param,
            "optional_param1": optional_param1,
            "optional_param2": optional_param2,
            "list_param": list_param,
            "list_of_lists": list_of_lists,
            "list_of_lists_list": list_of_lists_list,
            "dict_param": dict_param,
            "dict_of_lists": dict_of_lists,
            "dict_of_lists_of_dicts": dict_of_lists_of_dicts
        }

        return Response(result, status=status.HTTP_200_OK)
