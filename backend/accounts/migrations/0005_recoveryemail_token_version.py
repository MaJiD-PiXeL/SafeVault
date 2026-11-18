import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("accounts", "0004_secondfactor")]
    operations = [migrations.AddField(
        model_name="recoveryemail", name="token_version",
        field=models.UUIDField(default=uuid.uuid4, editable=False),
    )]
