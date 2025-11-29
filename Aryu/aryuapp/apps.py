from django.apps import AppConfig


class AryuappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'aryuapp'

    def ready(self):
        import aryuapp.signals  # ensures signals load on startup