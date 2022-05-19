from email.message import EmailMessage
from enum import Enum
import json
from multiprocessing import AuthenticationError
import random
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from urllib import request
from django.conf import settings
from django.http import BadHeaderError, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.core.mail import send_mail
from django.contrib.auth.models import User, auth
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from django.http.response import JsonResponse
from AskApp.models import Answers, Cat, Posts
from AskApp.serializers import AnswersSerializer, CategoriesSerializer, CategorySerializer, LoginSerializer, PasswordChangeSerializer, PasswordResetConfirmSerializer, PasswordResetSerializer, PublicationSerializer, UserSerializer, ansserializer, postSerializer, postserializer, userSerializer
from django.core.files.storage import default_storage
from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework import exceptions
from rest_framework import status, viewsets
from django.views.decorators.debug import sensitive_post_parameters

class PasswordResetView(GenericAPIView):
    """
    Calls Django Auth PasswordResetForm save method.
    Accepts the following POST parameters: email
    Returns the success/fail message.
    """
    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        # Return the success message with OK HTTP status
        return Response(
            {"detail": ("Password reset e-mail has been sent.")},
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(GenericAPIView):
    """
    Password reset e-mail link is confirmed, therefore
    this resets the user's password.
    Accepts the following POST parameters: token, uid,
        new_password1, new_password2
    Returns the success/fail message.
    """
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    
    def dispatch(self, *args, **kwargs):
        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"detail": ("Password has been reset with the new password.")}
        )


class PasswordChangeView(GenericAPIView):
    """
    Calls Django Auth SetPasswordForm save method.
    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """
    serializer_class = PasswordChangeSerializer
    permission_classes = (IsAuthenticated,)


    def dispatch(self, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": ("New password has been saved.")})





class Authentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        username = request.META.get('HTTP_X_USERNAME')
        if not username:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')

        return (user, None)


class ProfileView(APIView):
    authentication_classes = [SessionAuthentication,
                              BasicAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):

        content = {
            'user': str(request.user),  # `django.contrib.auth.User` instance.
            'auth': str(request.auth),  # None
        }
        return JsonResponse(content)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('date_joined')
    serializer_class = UserSerializer
    authentication_classes = (TokenAuthentication,)
    permission_classes = [IsAuthenticated]


class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        token, created = Token.objects.get_or_create(user=user)
        if user is not None:
            return JsonResponse({
                'token': token.key,
                'user_id': user.pk,
                'username': user.username,
                'last_name': user.last_name,
                'first_name': user.first_name,
                'email': user.email,
                'Education': user.account.Education,
                'Image': user.account.Image,
                'Function': user.account.Function,
                'MobileNumber': user.account.MobileNumber,
                'Address': user.account.Address,
                'last_login': user.last_login,
                'date_joined': user.date_joined,

            })

        else:
            return JsonResponse("invalid username or password")


@csrf_exempt
def userApi(request, id=0):
    if request.method == 'GET':
        users = User.objects.all()
        user_serializer = UserSerializer(users, many=True)

        return JsonResponse(user_serializer.data, safe=False)

    elif request.method == 'POST':
        user_data = JSONParser().parse(request)

        user_serializer = UserSerializer(data=user_data)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse("Added Successfully!!", safe=False)
        return JsonResponse("Failed to Add.", safe=False)

    elif request.method == 'PUT':
        user_data = JSONParser().parse(request)
        user = User.objects.get(username=user_data['username'])
        user_serializer = userSerializer(user, data=user_data)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse("Updated Successfully!!", safe=False)
        return JsonResponse("Failed to Update.", safe=False)

    elif request.method == 'DELETE':
        user = User.objects.get(id=id)
        user.delete()
        return JsonResponse("Deleted Succeffully!!", safe=False)


@csrf_exempt
def postApi(request, id=0):
    if request.method == 'GET':
        posts = Posts.objects.all()
        post_serializer = PublicationSerializer(posts, many=True)
        return JsonResponse(post_serializer.data, safe=False)

    elif request.method == 'POST':
        post_data = JSONParser().parse(request)
        post_serializer = postSerializer(data=post_data)
        if post_serializer.is_valid():
            post_serializer.save()
            subject = "New Post has been added "
            message = " Someone has added a new post "
            to_email = ["'ask.to.solve.etc@gmail.com'"]

            from_email = settings.EMAIL_HOST_USER
            if subject and message and from_email:

                send_mail(
                    'Subject - AskToSolve new post',
                    subject + ',\n' + message,
                    'sender@example.com',  # Admin
                    [
                        'khechine.ines@gmail.com',
                    ]
                )

            print(post_data, "success")
            # send_email(request)
            return JsonResponse("Added Successfully!!", safe=False)
            send_mail(text='Here is your password reset token',
                      subject='password reset token', from_email='', to_emails=[''])
        return JsonResponse("Failed to Add.", safe=False)

    elif request.method == 'PUT':
        post_data = JSONParser().parse(request)
        pubId = Posts.objects.get(pubId=post_data['pubId'])
        post_serializer = postSerializer(pubId, data=post_data)
        if post_serializer.is_valid():
            post_serializer.save()
            return JsonResponse("Updated Successfully!!", safe=False)
        return JsonResponse("Failed to Update.", safe=False)

    elif request.method == 'DELETE':
        post = Posts.objects.get(pubId=id)
        post.delete()
        return JsonResponse("Deleted Succeffully!!", safe=False)


@csrf_exempt
def answerApi(request, id=0):
    if request.method == 'GET':
        answers = Answers.objects.all()
        answers_serializer = AnswersSerializer(answers, many=True)
        return JsonResponse(answers_serializer.data, safe=False)

    elif request.method == 'POST':
        answers_data = JSONParser().parse(request)
        answers_serializer = ansserializer(data=answers_data)
        if answers_serializer.is_valid():
            answers_serializer.save()
            subject = " New Answer"
            message = " Someone has added a new answer to your post "
            to_email = ["'ask.to.solve.etc@gmail.com'"]

            from_email = settings.EMAIL_HOST_USER
            if subject and message and from_email:

                send_mail(
                    'Subject - AskToSolve new answer',
                    subject + ',\n' + message,
                    'sender@example.com',  # Admin
                    [
                        'khechine.ines@gmail.com',
                    ]
                )
            return JsonResponse("Added Successfully!!", safe=False)
        return JsonResponse("Failed to Add.", safe=False)

    elif request.method == 'PUT':
        answers_data = JSONParser().parse(request)
        answers = Answers.objects.get(answers=answers_data['AnswersId'])
        answers_serializer = AnswersSerializer(answers, data=answers_data)
        if answers_serializer.is_valid():
            answers_serializer.save()
            return JsonResponse("Updated Successfully!!", safe=False)
        return JsonResponse("Failed to Update.", safe=False)

    elif request.method == 'DELETE':
        ans = Answers.objects.get(AnsId=id)
        ans.delete()
        return JsonResponse("Deleted Succeffully!!", safe=False)


@csrf_exempt
def categoriesApi(request, id=0):
    if request.method == 'GET':
        categories = Cat.objects.all()
        categories_serializer = CategoriesSerializer(categories, many=True)
        return JsonResponse(categories_serializer.data, safe=False)

    elif request.method == 'POST':
        categories_data = JSONParser().parse(request)
        categories_serializer = CategorySerializer(data=categories_data)
        if categories_serializer.is_valid():
            categories_serializer.save()
            return JsonResponse("Added Successfully!!", safe=False)
        return JsonResponse("Failed to Add.", safe=False)

    elif request.method == 'PUT':
        categories_data = JSONParser().parse(request)
        CatId = Cat.objects.get(CatId=categories_data['CatId'])
        categories_serializer = CategorySerializer(CatId, data=categories_data)
        if categories_serializer.is_valid():
            categories_serializer.save()
            return JsonResponse("Updated Successfully!!", safe=False)
        return JsonResponse("Failed to Update.", safe=False)

    elif request.method == 'DELETE':
        categories = Cat.objects.get(CatId=id)
        categories.delete()
        return JsonResponse("Deleted Succeffully!!", safe=False)


@csrf_exempt
def SaveFile(request):
    file = request.FILES['uploadedFile']
    file_name = default_storage.save(file.name, file)

    return JsonResponse(file_name, safe=False)


def reset_password(request):
    print(request.method)
    if request.method == 'POST':
        reqbody = json.loads(request.body)
        token_recieved = reqbody['token']
        password = reqbody['password']
        password_again = reqbody['password2']
        print(request.user)
        used = User.objects.get(id=request.user.id)

        if token_recieved != used.random_integer:
            return Response('Invalid Token')

        if password != password_again:
            return Response('Passwords should match')
        used.random_integer = None
        used.save()
        return Response('Password changed successfully')

    token1 = random.randint(1000, 9999)
    print(request.user.email)
    used = User.objects.get(id=request.user.id)
    used.random_integer = token1
    used.save()

    send_mail(html=token1, text='Here is your password reset token',
              subject='password reset token', from_email='', to_emails=[''])

    return Response('working now')