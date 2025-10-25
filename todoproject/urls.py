from django.urls import path, include
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from todos.views import unauthorized

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/unauthorized/', unauthorized),
    path('api/', include('todos.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)