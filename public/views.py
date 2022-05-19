from django.shortcuts import render
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
class IndexView(APIView):
  

    def get(self, request, format=None):
        content = {
            'wmsg' : 'welcome to your account',
        }
        return Response(content)
