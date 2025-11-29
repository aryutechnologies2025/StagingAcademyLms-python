from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import *


urlpatterns = [
    path("host/login", HostLoginView.as_view()),
    path("host/register", HostCreateView.as_view()),
    path("host/list", HostListView.as_view()),
    # Question bank
    path("categories", QuestionCategoryListCreateView.as_view(), name="question-category-list-create"),
    path("questions", QuestionListCreateView.as_view(), name="question-list-create"),

    # Quiz rooms
    path("rooms", QuizRoomListCreateView.as_view(), name="quiz-room-list-create"),
    path("rooms/<uuid:pk>", QuizRoomDetailView.as_view(), name="quiz-room-detail"),

    # Participant
    path("join", JoinQuizRoomView.as_view(), name="join-quiz-room"),

    # Answers
    path("submit-answer", SubmitAnswerView.as_view(), name="submit-answer"),

    # Leaderboard
    path("leaderboard", LeaderboardView.as_view(), name="leaderboard"),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
