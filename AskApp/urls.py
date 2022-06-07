import statistics
from django.conf import settings
from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from django.conf.urls.static import static
from django.conf.urls import url
from AskApp import views
urlpatterns = [
    
    
    path('profile/', views.ProfileView.as_view()),
    path('api/auth/', views.CustomAuthToken.as_view()),
    url(r'^user/$', views.userApi),
    url(r'^user/([0-9]+)$', views.userApi),
    url(r'^post/$', views.postApi),
    url(r'^addpost/$', views.postApi),
    url(r'^SaveFile$', views.SaveFile),
    url(r'^post/([0-9]+)$', views.postApi),
    url(r'^ans/$', views.answerApi),
    url(r'^ans/([0-9]+)$', views.answerApi),
    url(r'^vote/$', views.voteApi),
    url(r'^vote/([0-9]+)$', views.voteApi),
    url(r'^categories/$', views.categoriesApi),
    url(r'^categories/([0-9]+)$', views.categoriesApi),
    url(r'^password/reset/$', views.PasswordResetView.as_view(),
        name='rest_password_reset'),
    url(r'^password/reset/confirm/$', views.PasswordResetConfirmView.as_view(),
        name='rest_password_reset_confirm'),
    url(r'^password/change/$', views.PasswordChangeView.as_view(),
        name='rest_password_change'),
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns = format_suffix_patterns(urlpatterns)
#urlpatterns = [
   # url(r'^user/$', views.userApi),
   # url(r'^user/([0-9]+)$', views.userApi),
   # url(r'^login/' , views.login),
#]