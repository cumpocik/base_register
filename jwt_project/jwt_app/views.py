from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import User
from django.utils import timezone
import hashlib
import datetime
import jwt
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from .models import RevokedToken
import logging

logger = logging.getLogger(__name__)

def index_view(request):
    return render(request, 'index.html')

def create_jwt_token(user):
    payload = {
        'id': user.id,
        'username': user.username,
        'exp': timezone.now() + datetime.timedelta(days=2)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return User.objects.get(id=payload['id'])
    except (jwt.DecodeError, User.DoesNotExist):
        return None

def logout_view(request):
    return redirect('/login')

def jwt_authentication_middleware(get_response):
    def middleware(request):
        token = request.COOKIES.get('jwt')
        if token:
            user = verify_jwt_token(token)
            if user:
                request.user = user
        response = get_response(request)
        return response
    return middleware

def refresh_token_view(request):
    token = request.COOKIES.get('jwt')
    if token:
        user = verify_jwt_token(token)
        if user:
            new_token = create_jwt_token(user, expiration=datetime.timedelta(days=2))
            response = JsonResponse({'jwt': new_token})
            response.set_cookie('jwt', new_token)
            logger.info(f"User {user.username} refreshed their token")
            return response
    return HttpResponseBadRequest("Invalid token")

def revoke_token_view(request):
    token = request.COOKIES.get('jwt')
    if token:
        user = verify_jwt_token(token)
        if user:
            token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
            RevokedToken.objects.create(token_hash=token_hash)
            logger.info(f"Token revoked for user {user.username}")
            return JsonResponse({'message': 'Token revoked successfully'})
    return HttpResponseBadRequest("Invalid token")

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        try:
            user = User.objects.get(username=username, password=hashed_password)
            token = create_jwt_token(user)
            response = redirect('/')
            response.set_cookie('jwt', token)
            return response
        except User.DoesNotExist:
            return render(request, 'login.html', {'error': 'Неверное имя пользователя или пароль'})
    else:
        return render(request, 'login.html')

def registration_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if User.objects.filter(username=username).exists():
            return render(request, 'registration.html', {'error': 'Такое имя пользователя уже существует'})

        if password == confirm_password:
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user = User.objects.create_user(username=username, password=hashed_password)
            return redirect('/login')
        else:
            return render(request, 'registration.html', {'error': 'Пароли не совпадают'})
    else:
        return render(request, 'registration.html')