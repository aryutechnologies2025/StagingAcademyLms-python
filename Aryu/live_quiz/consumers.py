import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils import timezone
from django.shortcuts import get_object_or_404

from .models import QuizRoom, QuizRoomQuestion
from .utils import build_leaderboard


class QuizConsumer(AsyncWebsocketConsumer):
    """
    WebSocket URL: ws://.../ws/quiz/<room_id>/

    Actions from frontend (JSON):
    - { "action": "join", "name": "..."}  (optional if you want)
    - { "action": "start_quiz" }          (host)
    - { "action": "start_question", "order": 1 } (host)
    - { "action": "end_quiz" }            (host)
    - { "action": "get_leaderboard" }
    """

    async def connect(self):
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]
        self.group_name = f"quiz_{self.room_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        data = json.loads(text_data)
        action = data.get("action")

        if action == "start_quiz":
            await self.handle_start_quiz()
        elif action == "start_question":
            order = data.get("order")
            await self.handle_start_question(order)
        elif action == "end_quiz":
            await self.handle_end_quiz()
        elif action == "get_leaderboard":
            await self.handle_get_leaderboard()
        else:
            # unknown action
            await self.send(json.dumps({"type": "error", "message": "Unknown action"}))

    async def handle_start_quiz(self):
        room = get_object_or_404(QuizRoom, id=self.room_id)
        if not room.started_at:
            room.started_at = timezone.now()
        room.is_live = True
        room.save(update_fields=["started_at", "is_live"])

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "quiz.started",
                "message": "Quiz has started",
            }
        )

    async def handle_start_question(self, order):
        if order is None:
            await self.send(json.dumps({"type": "error", "message": "order required"}))
            return

        room_question = get_object_or_404(
            QuizRoomQuestion, room_id=self.room_id, order=order
        )
        now = timezone.now()
        room_question.started_at = now
        room_question.ended_at = None
        room_question.save(update_fields=["started_at", "ended_at"])

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "question.started",
                "room_question_id": room_question.id,
                "order": room_question.order,
                "time_limit": room_question.time_limit,
                "marks": room_question.marks,
                "question": {
                    "id": room_question.question.id,
                    "text": room_question.question.text,
                    "options": room_question.question.options,
                },
                "started_at": now.isoformat(),
            }
        )

    async def handle_end_quiz(self):
        room = get_object_or_404(QuizRoom, id=self.room_id)
        room.is_live = False
        room.ended_at = timezone.now()
        room.save(update_fields=["is_live", "ended_at"])

        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "quiz.ended",
                "message": "Quiz has ended",
            }
        )

    async def handle_get_leaderboard(self):
        room = get_object_or_404(QuizRoom, id=self.room_id)
        leaderboard_data = build_leaderboard(room)
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "leaderboard.update",
                "leaderboard": leaderboard_data,
            }
        )

    # ---------- Handlers for messages sent to group ----------

    async def quiz_started(self, event):
        await self.send(json.dumps({
            "type": "quiz_started",
            "message": event.get("message"),
        }))

    async def quiz_ended(self, event):
        await self.send(json.dumps({
            "type": "quiz_ended",
            "message": event.get("message"),
        }))

    async def question_started(self, event):
        await self.send(json.dumps({
            "type": "question_started",
            "room_question_id": event["room_question_id"],
            "order": event["order"],
            "time_limit": event["time_limit"],
            "marks": event["marks"],
            "question": event["question"],
            "started_at": event["started_at"],
        }))

    async def leaderboard_update(self, event):
        await self.send(json.dumps({
            "type": "leaderboard_update",
            "leaderboard": event["leaderboard"],
        }))
