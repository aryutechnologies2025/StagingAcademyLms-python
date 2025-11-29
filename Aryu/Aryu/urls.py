from django.contrib import admin
import os
from django.urls import path,include, re_path
from django.http import FileResponse, JsonResponse
from django.conf import settings


def api_root_hidden(request):
    return JsonResponse({'success': False, 'message': 'API root is hidden.'}, status=404)

def serve_media(request, path):
    # Optional: restrict access to logged-in users or staff
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'message': 'Unauthorized access'}, status=403)

    file_path = os.path.join(settings.MEDIA_ROOT, path)

    # Prevent directory traversal attacks (like ../../etc/passwd)
    if not os.path.abspath(file_path).startswith(os.path.abspath(settings.MEDIA_ROOT)):
        return JsonResponse({'success': False, 'message': 'Invalid file path'}, status=400)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(open(file_path, "rb"))
    else:
        return JsonResponse({'success': False, 'message': 'File not found'}, status=404)

def custom_404_view(request, exception=None):
    return JsonResponse({'success': False, 'message': 'The requested URL was not found on this server.'}, status=404)

handler404 = custom_404_view

def custom_500_view(request):
    return JsonResponse({'success': False, 'message': 'An internal server error occurred.'}, status=500)

handler500 = custom_500_view

urlpatterns = [
    path('api/admin/', admin.site.urls),

    # Hide the root /api/
    path("api/", api_root_hidden),

    # Include your actual API endpoints (they’ll still work like /api/courses/, /api/auth/, etc.)
    path("api/", include("aryuapp.urls")),

    path("api/live-quiz/", include("live_quiz.urls")),
    
    re_path(r'^api/media/(?P<path>.*)$', serve_media, name='serve_media'),
]


