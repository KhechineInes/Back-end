
from dataclasses import fields
import profile
from rest_framework.authtoken.models import Token
from rest_framework import serializers

from django.contrib.auth.models import User

from AskApp.models import Answers, Cat, Posts
from AsktoSolve import settings
from allauth.account.adapter import get_adapter

from .models import Profile, User, Vote
from allauth.account.utils import setup_user_email

from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import force_text

from rest_framework import serializers, exceptions
from rest_framework.exceptions import ValidationError


from .utils import import_callable

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=Profile
        fields=['Education',
                'Function',
                'Image',
                'Address',
                'MobileNumber']
 
  

class UserSerializer(serializers.ModelSerializer):
  
    owner = serializers.ReadOnlyField(source='owner.username')
    account=ProfileSerializer()

    class Meta:
        model = User
        fields = ('id','last_login','first_name','last_name', 'username', 'password','owner', 'date_joined' ,'email','account'  )
        extra_kwargs = {'password': {'write_only': True , 'required': True}} 

   
class user(serializers.ModelSerializer)  :
    account=ProfileSerializer()
    class Meta:
       
        model = User
        fields = ('id','username', 'password' ,'email','account')
    
# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])
        #token, created = Token.objects.get_or_create(user=user)
        return user
 
    
    
    
    
    
    
    
    
    
    
    
class postserializer(serializers.ModelSerializer):
    class Meta:
        model = Posts
        fields = ('pubId',
                  'pubsubject',
                  'pub',
                  'cat_id',
                  'user_id')
    
    
    
    
    
    
    
    
    
class AnswersSerializer(serializers.ModelSerializer):
    user=UserSerializer()
    pub_id=postserializer()
    
    owner = serializers.ReadOnlyField(source='owner.username') #important
    class Meta:
        model = Answers
        fields = ('AnsId',
                  'Ans',
                  'pub_id',
                  'date',
                  'user',
                  'user',
                  'owner',
                  )
        
        
class VoteSerializer(serializers.ModelSerializer):
    user_id=UserSerializer()
    post_id=postserializer()
    ans_id=AnswersSerializer()
    owner = serializers.ReadOnlyField(source='owner.username') #important
    class Meta:
        model = Vote
        fields = ('VoteId',
                  'Positive',
                  'Negative',
                  'post_id',
                  'ans_id',
                  'date',
                  'user_id',
                  'owner',
                  )
           
        
        
class CategoriesSerializer(serializers.ModelSerializer):

    owner = serializers.ReadOnlyField(source='owner.username') #important    
    class Meta:
        model = Cat
        fields = ('CatId',
                  'CatName',
                  'CatFramework',
                  'CatLang',
                  'Image',
                  'owner',
                  
                  

                  )    









class PublicationSerializer(serializers.ModelSerializer):
    user=UserSerializer()
    
    cat=CategoriesSerializer()
    owner = serializers.ReadOnlyField(source='owner.username') #important
    class Meta:
        model = Posts
        fields = ('pubId',
                  'pub',
                  'date',
                  'pubsubject',
                  'user_id',
                  
                  'user',
                   'cat_id',
                  'cat','owner'
                  




                  )
class userSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields=('id','username' , 'first_name' , 'last_name' ,'email')
        


    
    
class postserializer(serializers.ModelSerializer):
    
    class Meta:
        model = Posts
        fields = ('pubId',
                  'pubsubject',
                  'pub',
                  
                  
                  
                  
                  )
class postSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Posts
        fields = ('pubId',
                  'pubsubject',
                  'pub',
                  'user',
                  'cat',
                  
                  
                  
                  )
class ansserializer(serializers.ModelSerializer):
    
    class Meta:
        model = Answers
        fields = ('AnsId',
                  'Ans',
                  'pub_id',
                  'user',
                  
                  
                  
                  )

class CategorySerializer(serializers.ModelSerializer):
    
    
    class Meta:
        model = Cat
        fields = (
            'CatId',
            'CatName',
            'CatFramework',
            'CatLang',
            'Image',
            
            
             )    
   
