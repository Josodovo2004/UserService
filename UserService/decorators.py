from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

def jwt_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        auth = JWTAuthentication()
        try:
            # Try to authenticate the token
            auth_result = auth.authenticate(request)
            if auth_result is None:
                return Response({'detail': 'Authentication credentials were not provided.'}, status=401)

            # Attach the user to the request
            request.user, token = auth_result

        except (InvalidToken, TokenError) as e:
            return Response({'detail': 'Invalid token'}, status=401)

        return view_func(request, *args, **kwargs)

    return _wrapped_view
