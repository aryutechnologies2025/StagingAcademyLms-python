from rest_framework import serializers
from .models import *
import qrcode
import base64
import os
from io import BytesIO



class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = "__all__"


class HostLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class QuestionCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = QuestionCategory
        fields = ["id", "name", "description"]


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = [
            "id",
            "category",
            "text",
            "options",
            "correct_key",
            "default_time_limit",
            "default_marks",
            "is_active",
        ]


class QuizRoomQuestionSerializer(serializers.ModelSerializer):
    question = QuestionSerializer(read_only=True)
    question_id = serializers.PrimaryKeyRelatedField(
        source="question",
        queryset=Question.objects.filter(is_active=True),
        write_only=True
    )

    class Meta:
        model = QuizRoomQuestion
        fields = [
            "id",
            "room",
            "question",
            "question_id",
            "order",
            "time_limit",
            "marks",
            "started_at",
            "ended_at",
        ]
        read_only_fields = ["room", "started_at", "ended_at"]


class QuizRoomSerializer(serializers.ModelSerializer):
    room_questions = QuizRoomQuestionSerializer(many=True, write_only=True, required=False)
    questions = QuizRoomQuestionSerializer(many=True, read_only=True, source="room_questions")
    qr_url = serializers.CharField(read_only=True)

    class Meta:
        model = QuizRoom
        fields = [
            "id",
            "title",
            "host",
            "category",
            "is_live",
            "created_at",
            "started_at",
            "ended_at",
            "room_questions",
            "questions",
            "qr_url",
        ]
        read_only_fields = ["created_at", "started_at", "ended_at", "qr_url"]

    def create(self, validated_data):
        room_questions_data = validated_data.pop("room_questions", [])

        # Create room first
        room = QuizRoom.objects.create(**validated_data)

        order_counter = 1
        for rq in room_questions_data:
            question = rq["question"]
            time_limit = rq.get("time_limit") or question.default_time_limit
            marks = rq.get("marks") or question.default_marks

            QuizRoomQuestion.objects.create(
                room=room,
                question=question,
                order=rq.get("order", order_counter),
                time_limit=time_limit,
                marks=marks,
            )
            order_counter += 1

        # ---------------------------
        # Generate QR Code Image
        # ---------------------------
        # qr_data = f"https://aylms.aryuprojects.com/quiz-join?room_id={room.id}"
        qr_data = f"https://aylms.aryuprojects.com/login"

        qr_img = qrcode.make(qr_data)

        qr_folder = os.path.join(settings.MEDIA_ROOT, "qr")
        os.makedirs(qr_folder, exist_ok=True)

        qr_filename = f"{room.id}.png"
        qr_path = os.path.join(qr_folder, qr_filename)

        qr_img.save(qr_path)

        # Return URL
        room.qr_url = f"https://aylms.aryuprojects.com/api/media/qr/{qr_filename}"

        return room


class ParticipantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Participant
        fields = ["id", "room", "name", "email", "phone", "joined_at"]
        read_only_fields = ["joined_at"]


class ParticipantAnswerSerializer(serializers.ModelSerializer):
    class Meta:
        model = ParticipantAnswer
        fields = [
            "id",
            "participant",
            "room_question",
            "selected_key",
            "is_correct",
            "score",
            "answered_at",
        ]
        read_only_fields = ["is_correct", "score", "answered_at"]
