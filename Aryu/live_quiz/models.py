from django.db import models

# Create your models here.
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class Host(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, unique=True)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."hosts'

    def __str__(self):
        return self.name

class QuestionCategory(models.Model):

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."question_categories'


class Question(models.Model):

    category = models.ForeignKey(
        QuestionCategory, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="questions"
    )
    text = models.TextField()
    # List of options: [{ "key": "A", "text": "Option 1" }, ...]
    options = models.JSONField()
    correct_key = models.CharField(max_length=10)  # e.g., "A", "B"
    default_time_limit = models.PositiveIntegerField(default=10)  # seconds
    default_marks = models.PositiveIntegerField(default=10)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."questions'

    def __str__(self):
        return self.text[:60]


class QuizRoom(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    host = models.ForeignKey(
        Host, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="hosted_quiz_rooms"
    )
    category = models.ForeignKey(
        QuestionCategory, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="quiz_rooms"
    )
    is_live = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."quiz_rooms'

    def __str__(self):
        return self.title


class QuizRoomQuestion(models.Model):

    room = models.ForeignKey(
        QuizRoom, on_delete=models.CASCADE, related_name="room_questions"
    )
    question = models.ForeignKey(
        Question, on_delete=models.CASCADE, related_name="question_in_rooms"
    )
    order = models.PositiveIntegerField()  # 1, 2, 3...
    time_limit = models.PositiveIntegerField()  # seconds
    marks = models.PositiveIntegerField()
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."quiz_room_questions'
        unique_together = ("room", "order")
        ordering = ["order"]

    def __str__(self):
        return f"{self.room.title} - Q{self.order}"


class Participant(models.Model):

    room = models.ForeignKey(
        QuizRoom, on_delete=models.CASCADE, related_name="participants"
    )
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."participants'

    def __str__(self):
        return f"{self.name} ({self.room.title})"


class ParticipantAnswer(models.Model):

    participant = models.ForeignKey(
        Participant, on_delete=models.CASCADE, related_name="answers"
    )
    room_question = models.ForeignKey(
        QuizRoomQuestion, on_delete=models.CASCADE, related_name="answers"
    )
    selected_key = models.CharField(max_length=10)  # e.g. "A", "B"
    is_correct = models.BooleanField(default=False)
    score = models.FloatField(default=0)
    answered_at = models.DateTimeField(auto_now_add=True)
    # To prevent multiple answers for same question:
    class Meta:
        app_label = "live_quiz"
        db_table = 'livequiz"."answers'

    def __str__(self):
        return f"{self.participant.name} - {self.room_question}"
