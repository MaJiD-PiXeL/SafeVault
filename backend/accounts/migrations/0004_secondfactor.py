from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0003_schedule_password_reset_retries"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [migrations.CreateModel(name="SecondFactor", fields=[
        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
        ("encrypted_secret", models.TextField()),
        ("enabled", models.BooleanField(default=False)),
        ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
        ("last_counter", models.BigIntegerField(default=-1)),
        ("recovery_hashes", models.JSONField(default=list)),
        ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
    ])]
