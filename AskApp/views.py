from email.message import EmailMessage
from enum import Enum
import json
from multiprocessing import AuthenticationError
import random
from django.views.decorators.debug import sensitive_post_parameters
from numpy import generic
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
from AskApp.models import Answers, Cat, Posts, Profile, Vote
from AskApp.serializers import AnswersSerializer, CategoriesSerializer, CategorySerializer, ChangePasswordSerializer, ProfileSerializer, PublicationSerializer, RegisterSerializer, UserSerializer, VoteSerializer, ansserializer, postSerializer, userSerializer, voteSerializer
from django.core.files.storage import default_storage
from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework import exceptions
from rest_framework import status, viewsets
from django.views.decorators.debug import sensitive_post_parameters
from rest_framework import generics, permissions
from rest_framework import status
from rest_framework import generics
from rest_framework.response import Response
from django.contrib.auth.models import User
from . import serializers
from rest_framework.permissions import IsAuthenticated 







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
                'email': user.email,
                'Function': user.account.Function
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
        
        serializer = UserSerializer(data=user_data)
        if serializer.is_valid():
            user = serializer.save()
            return JsonResponse({
                   
                   "user": UserSerializer(user).data,
                   "token": Token.objects.create(user=user)[1]})
        return JsonResponse("Failed to Add", safe=False)
       
       

    elif request.method == 'PUT':
        user_data = JSONParser().parse(request)
        user = User.objects.get(username=user_data['username'])
        user_serializer = userSerializer(user, data=user_data)
        
        Id = Profile.objects.get(account_id=user_data['id'])
        profile_serializer = ProfileSerializer(Id, data=user_data)
        if user_serializer.is_valid() and  profile_serializer.is_valid():
            user_serializer.save()
            profile_serializer.save()           
            return JsonResponse("Updated Successfully!!", safe=False)
        return JsonResponse("Failed to Update.", safe=False)

    elif request.method == 'DELETE':
        user = User.objects.get(id=id)
        user.delete()
        return JsonResponse("Deleted Succeffully!!", safe=False)

# Register API
class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
       # return Response({
       # "user": UserSerializer(user, context=self.get_serializer_context()).data,
        #"token": Token.objects.create(user=user)
       
        #})
        return JsonResponse("Added Successfully", safe=False
                            )
class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
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
def voteApi(request, id=0):
    if request.method == 'GET':
        votes = Vote.objects.all()
        vote_serializer = VoteSerializer(votes, many=True)
        return JsonResponse(vote_serializer.data, safe=False)

    elif request.method == 'POST':
        vote_data = JSONParser().parse(request)
        Vote_serializer = VoteSerializer(data=vote_data)
        if Vote_serializer.is_valid():
            Vote_serializer.save()
            return JsonResponse("Added Successfully!!", safe=False)
        return JsonResponse("Failed to Add.", safe=False)

  

    elif request.method == 'DELETE':
        ans = Answers.objects.get(VoteId=id)
        ans.delete()
        return JsonResponse("Deleted Succeffully!!", safe=False)

@csrf_exempt
def getUserVotedApi(request, id=0):
    if request.method == 'GET':
        votes = Vote.objects.all()
        vote_serializer = voteSerializer(votes, many=True)
        return JsonResponse(vote_serializer.data, safe=False)
@csrf_exempt
def ProfileApi(request, id=0):
    if request.method == 'GET':
        profile = Profile.objects.all()
        profile_serializer = ProfileSerializer(profile, many=True)
        return JsonResponse(profile_serializer.data, safe=False)

    elif request.method == 'POST':
        profiles_data = JSONParser().parse(request)
        profile_serializer = ProfileSerializer(data=profiles_data)
        if profile_serializer.is_valid():
            profile_serializer.save()
            return JsonResponse("Added Successfully!!", safe=False)
        return JsonResponse("Failed to Add.", safe=False)

    elif request.method == 'PUT':
        profiles_data = JSONParser().parse(request)
        Id = Profile.objects.get(CatId=profiles_data['id'])
        profile_serializer = ProfileSerializer(Id, data=profiles_data)
        if profile_serializer.is_valid():
            profile_serializer.save()
            return JsonResponse("Updated Successfully!!", safe=False)
        return JsonResponse("Failed to Update.", safe=False)

    elif request.method == 'DELETE':
        profile = Profile.objects.get(Id=id)
        profile.delete()
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
