from django.shortcuts import render

# Create your views here.
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Sum
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.hashers import make_password, check_password
from .models import *
from .serializers import *
from .utils import calculate_score_for_answer, build_leaderboard
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer



class HostCreateView(generics.CreateAPIView):
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    def perform_create(self, serializer):
        password = serializer.validated_data.get("password")
        serializer.save(password=make_password(password))

class HostListView(generics.ListAPIView):
    queryset = Host.objects.all()
    serializer_class = HostSerializer

class HostLoginView(APIView):
    def post(self, request):
        serializer = HostLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            try:
                host = Host.objects.get(email=email)
            except Host.DoesNotExist:
                return Response({"success": False, "message": "Host not found"}, status=400)

            if check_password(password, host.password):
                return Response({"success": True, "host_id": host.id})
            else:
                return Response({"success": False, "message": "Incorrect password"}, status=400)

        return Response(serializer.errors, status=400)


# ---------- Question Bank APIs ----------

class QuestionCategoryListCreateView(generics.ListCreateAPIView):


    queryset = QuestionCategory.objects.all()
    serializer_class = QuestionCategorySerializer
    permission_classes = [AllowAny]  # adjust as needed


class QuestionListCreateView(generics.ListCreateAPIView):
    queryset = Question.objects.all()
    serializer_class = QuestionSerializer
    permission_classes = [AllowAny]  # host side to create questions


# ---------- Quiz Room APIs ----------

class QuizRoomListCreateView(generics.ListCreateAPIView):

    queryset = QuizRoom.objects.all()
    serializer_class = QuizRoomSerializer
    permission_classes = [AllowAny]


class QuizRoomDetailView(generics.RetrieveAPIView):
    queryset = QuizRoom.objects.all()
    serializer_class = QuizRoomSerializer
    permission_classes = [AllowAny]


# ---------- Participant Join API ----------

class JoinQuizRoomView(APIView):
    """
    Viewer scans QR, frontend calls this.
    POST /api/live-quiz/join/
    {
        "room_id": "<uuid>",
        "name": "...",
        "email": "...",
        "phone": "..."
    }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        room_id = request.data.get("room_id")
        name = request.data.get("name")
        email = request.data.get("email")
        phone = request.data.get("phone")

        if not all([room_id, name, email, phone]):
            return Response(
                {"success": False, "message": "Missing fields"},
                status=status.HTTP_400_BAD_REQUEST
            )

        room = get_object_or_404(QuizRoom, id=room_id)

        participant = Participant.objects.create(
            room=room,
            name=name,
            email=email,
            phone=phone,
        )

        return Response(
            {
                "success": True,
                "participant_id": participant.id,
                "room_id": str(room.id),
                "room_title": room.title,
            },
            status=status.HTTP_201_CREATED,
        )


# ---------- Answer Submission API ----------

class SubmitAnswerView(APIView):
    """
    Participant submits answer.
    POST /api/live-quiz/submit-answer/
    {
        "participant_id": 5,
        "room_question_id": 12,
        "selected_key": "A"
    }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        participant_id = request.data.get("participant_id")
        room_question_id = request.data.get("room_question_id")
        selected_key = request.data.get("selected_key")

        if not all([participant_id, room_question_id, selected_key]):
            return Response(
                {"success": False, "message": "Missing fields"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        participant = get_object_or_404(Participant, id=participant_id)
        room_question = get_object_or_404(QuizRoomQuestion, id=room_question_id)

        # Prevent duplicate submission
        if ParticipantAnswer.objects.filter(
            participant=participant,
            room_question=room_question
        ).exists():
            return Response(
                {"success": False, "message": "Already answered"},
                status=status.HTTP_200_OK,
            )

        now = timezone.now()
        score = calculate_score_for_answer(room_question, now)

        correct_key = room_question.question.correct_key
        is_correct = (selected_key == correct_key)
        if not is_correct:
            # Incorrect = 0 score
            score = 0

        answer = ParticipantAnswer.objects.create(
            participant=participant,
            room_question=room_question,
            selected_key=selected_key,
            is_correct=is_correct,
            score=score,
            answered_at=now,
        )

        # Broadcast leaderboard update via WebSocket
        channel_layer = get_channel_layer()
        leaderboard_data = build_leaderboard(participant.room)
        async_to_sync(channel_layer.group_send)(
            f"quiz_{participant.room.id}",
            {
                "type": "leaderboard.update",
                "leaderboard": leaderboard_data,
            }
        )

        return Response(
            {
                "success": True,
                "is_correct": is_correct,
                "score": score,
            },
            status=status.HTTP_201_CREATED,
        )


# ---------- Leaderboard API ----------

class LeaderboardView(APIView):
    """
    GET /api/live-quiz/leaderboard?room_id=<uuid>
    """
    permission_classes = [AllowAny]

    def get(self, request):
        room_id = request.query_params.get("thor")

        if not room_id:
            return Response(
                {"success": False, "message": "room_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        room = get_object_or_404(QuizRoom, id=room_id)
        data = build_leaderboard(room)

        return Response({
            "success": True,
            "leaderboard": data
        })

