from asyncio import AbstractServer
from datetime import timezone
from ipaddress import AddressValueError
from typing import AbstractSet
from django.db import models

from django.contrib.auth.models import User , AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from rest_framework.authtoken.models import Token

from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.utils import timezone


class UserManager(BaseUserManager):

    def _create_user(self, username, email, password, is_staff, is_superuser, **extra_fields):
        now = timezone.now()
        if not username:
            raise ValueError(('The given username must be set'))
        email = self.normalize_email(email)
        user = self.model(username=username, email=email,
                          is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, last_login=now,
                          date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, password=None, **extra_fields):
        return self._create_user(username, email, password, False, False, ' ',
                                 **extra_fields)

    def create_superuser(self, username, email, password, **extra_fields):
        user = self._create_user(username, email, password, True, True,
                                 **extra_fields)
        user.is_active = True
        user.save(using=self._db)
        return user



        
        
class response(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=100, blank=False)
    content = models.TextField()
    author = models.CharField(max_length=100, blank=False)
    #owner = models.ForeignKey('auth.user', related_name='posts', on_delete=models.CASCADE)


owner = models.ForeignKey('auth.User', related_name='snippets', on_delete=models.CASCADE)
highlighted = models.TextField()

class profile(models.Model):
    
    account = models.OneToOneField(User,related_name='account',  on_delete=models.CASCADE)
    Image= models.CharField(max_length=255)
    Education= models.CharField(max_length=255, null=True)
    Function= models.CharField(max_length=255 , null=True)
    Address= models.CharField(max_length=255, null=True)
    MobileNumber= models.IntegerField()
    


    
    

    
    
class Cat(models.Model):
    
    CatId= models.AutoField(primary_key=True)
    CatName = models.CharField(max_length=100)
    CatFramework = models.CharField(max_length = 100)
    CatLang = models.CharField(max_length = 100)
    Image = models.CharField(max_length=255) 
    
class Posts(models.Model):
    cat= models.ForeignKey(Cat,null=True,on_delete=models.CASCADE,related_name='cate')
    user= models.ForeignKey(User,null=True,on_delete=models.CASCADE,related_name='posts')
   
    pubId = models.AutoField(primary_key=True)
    pubsubject = models.CharField(max_length=255)
    pub = models.CharField(max_length=255)
    date = models.DateTimeField(auto_now_add=True)    
   
class Answers(models.Model):
    user= models.ForeignKey(User,null=True,on_delete=models.CASCADE,related_name='ans')
    AnsId = models.AutoField(primary_key=True)
    Ans = models.CharField(max_length=255)
    date = models.DateTimeField(auto_now_add=True)
    pub_id = models.ForeignKey(Posts,null=True,on_delete=models.CASCADE,related_name='anspub')

class Vote(models.Model):
    user_id= models.ForeignKey(User,null=True,on_delete=models.CASCADE,related_name='user')
    VoteId = models.AutoField(primary_key=True)
    Positive= models.IntegerField(null=True)
    Negative= models.IntegerField(null=True )
    date = models.DateTimeField(auto_now_add=True)
    post_id = models.ForeignKey(Posts,null=True,on_delete=models.CASCADE,related_name='poste')
    ans_id = models.ForeignKey(Answers,null=True,on_delete=models.CASCADE,related_name='ans')