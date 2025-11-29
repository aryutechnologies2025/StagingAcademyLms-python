from django.db.models import Sum
from django.utils import timezone

from .models import QuizRoomQuestion, ParticipantAnswer, Participant


def calculate_score_for_answer(room_question: QuizRoomQuestion, answer_time) -> float:
    """
    Score based on how fast they answered.
    - If answered after time limit -> 0.
    - Faster => higher score.
    """
    if not room_question.started_at:
        # If we don't know start time, give 0 to be safe
        return 0

    elapsed = (answer_time - room_question.started_at).total_seconds()
    if elapsed <= 0:
        elapsed = 0.01  # avoid division issues

    if elapsed > room_question.time_limit:
        return 0

    remaining = room_question.time_limit - elapsed
    score = (remaining / room_question.time_limit) * room_question.marks
    return round(score, 2)


def build_leaderboard(room):
    """
    Returns list of participants with total_score ordered desc.
    """
    qs = (
        Participant.objects.filter(room=room)
        .annotate(total_score=Sum("answers__score"))
        .order_by("-total_score", "joined_at")
    )

    data = []
    rank = 1
    for p in qs:
        data.append({
            "rank": rank,
            "participant_id": p.id,
            "name": p.name,
            "email": p.email,
            "phone": p.phone,
            "total_score": float(p.total_score or 0),
        })
        rank += 1
    return data
