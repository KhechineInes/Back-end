from rest_framework.views import APIView
from requests import Response

from AsktoSolve import settings
from django.core.mail import send_mail
from rest_framework import status , viewsets
from enum import Enum

class HttpResponseCode(Enum):
    success= 200
    Failed = 400
    
    
class HttpRedirectUrl(Enum):
    email_code_verification ='/'
    
    
def response_code(code):
    if code == HttpResponseCode.success:
        return status.HTTP_200_OK
    elif code == HttpResponseCode.Failed:
        return status.HTTP_400_BAD_REQUEST


 
def create_response(code=None, message=None , success=None, redirect=None):
    status=response_code(code)
    response = {'success': success, 'message': message}
    if redirect != None:
        response['redirect'] = redirect
    return Response (data=response )
class send_email(APIView):
    
        
        
    def send_email(obj):
        subject = obj['subject']
        message = obj['message']
        to_email = obj['to_email']
        from_email = settings.EMAIL_HOST_USER
        if subject and message and from_email :
        
                send_mail(subject, message,from_email, to_email)
            
                
                return create_response(HttpResponseCode.success,'Email has been sent successfully' , redirect=HttpRedirectUrl.email_Code_Verification)
        else :
            return create_response(HttpResponseCode.Failed, 'Fields data is not valid ' , False)