from django.urls import path
from .consumers import QuizConsumer

websocket_urlpatterns = [
    path("ws/quiz/<uuid:room_id>/", QuizConsumer.as_asgi()),
]
