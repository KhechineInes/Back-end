
from dataclasses import fields
from rest_framework.authtoken.models import Token
from rest_framework import serializers

from django.contrib.auth.models import User

from AskApp.models import Answers, Cat, Posts, profile
from AsktoSolve import settings
from allauth.account.adapter import get_adapter

from .models import User
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

# Get the UserModel
UserModel = get_user_model()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def authenticate(self, **kwargs):
        return authenticate(self.context['request'], **kwargs)

    def _validate_email(self, email, password):
        user = None

        if email and password:
            user = self.authenticate(email=email, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username(self, username, password):
        user = None

        if username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username_email(self, username, email, password):
        user = None

        if email and password:
            user = self.authenticate(email=email, password=password)
        elif username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include either "username" or "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        user = None

        if 'allauth' in settings.INSTALLED_APPS:
            from allauth.account import app_settings

            # Authentication through email
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
                user = self._validate_email(email, password)

            # Authentication through username
            elif app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
                user = self._validate_username(username, password)

            # Authentication through either username or email
            else:
                user = self._validate_username_email(username, email, password)

        else:
            # Authentication without using allauth
            if email:
                try:
                    username = UserModel.objects.get(email__iexact=email).get_username()
                except UserModel.DoesNotExist:
                    pass

            if username:
                user = self._validate_username_email(username, '', password)

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(_('E-mail is not verified.'))

        attrs['user'] = user
        return attrs





class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    email = serializers.EmailField()

    password_reset_form_class = PasswordResetForm

    def get_email_options(self):
        """Override this method to change default e-mail options"""
        return {}

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return value

    def save(self):
        request = self.context.get('request')
        # Set some values to trigger the send_email method.
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'request': request,
        }

        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        self._errors = {}

        # Decode the uidb64 to uid to get User object
        try:
            uid = force_text(uid_decoder(attrs['uid']))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise ValidationError({'uid': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs['token']):
            raise ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
        return self.set_password_form.save()


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = getattr(
            settings, 'OLD_PASSWORD_FIELD_ENABLED', False
        )
        self.logout_on_password_change = getattr(
            settings, 'LOGOUT_ON_PASSWORD_CHANGE', False
        )
        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop('old_password')

        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            err_msg = _("Your old password was entered incorrectly. Please enter it again.")
            raise serializers.ValidationError(err_msg)
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()
        if not self.logout_on_password_change:
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(self.request, self.user)



class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(required=settings.ACCOUNT_EMAIL_REQUIRED)
    first_name = serializers.CharField(required=False, write_only=True)
    last_name = serializers.CharField(required=False, write_only=True)
    address = serializers.CharField(required=False, write_only=True)

    password1 = serializers.CharField(required=True, write_only=True)
    password2 = serializers.CharField(required=True, write_only=True)

    def validate_password1(self, password):
        return get_adapter().clean_password(password)

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError(
                ("The two password fields didn't match."))
        return data

    def custom_signup(self, request, user):
        pass

    def get_cleaned_data(self):
        return {
            'first_name': self.validated_data.get('first_name', ''),
            'last_name': self.validated_data.get('last_name', ''),
            'address': self.validated_data.get('address', ''),
            'user_type': self.validated_data.get('user_type', ''),
            'password1': self.validated_data.get('password1', ''),
            'email': self.validated_data.get('email', ''),
        }

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        adapter.save_user(request, user, self)
        self.custom_signup(request, user)
        setup_user_email(request, user, [])
        user.save()
        return user


class UserDetailsSerializer(serializers.ModelSerializer):
    """
    User model w/o password
    """
    class Meta:
        model = User
        fields = ('pk', 'username', 'email', 'first_name',
                  'last_name', 'address', 'city', 'about_me', 'profile_image')
        read_only_fields = ('email', )
        
        
        
        
        
        
        
        
        

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=profile
        fields=['Image']
 
 
 
 
 
 
        
class UserSerializer(serializers.ModelSerializer):
    account=ProfileSerializer()
    owner = serializers.ReadOnlyField(source='owner.username')
    

    class Meta:
        model = User
        fields = ('id','last_login', 'username', 'password','owner', 'date_joined' ,'email','account'  )
        extra_kwargs = {'password': {'write_only': True , 'required': True}}
   
    def create(self,validated_data):
        user=User.objects.create_user(**validated_data)
        user.save()
        Token.objects.create(user=user)
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
   
