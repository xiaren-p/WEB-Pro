# Replaces previous removed 0002_add_tag_type_to_dictitem; depends on latest migration.
from django.db import migrations, models

class Migration(migrations.Migration):
    # Mark that this migration replaces the earlier mistakenly added 0002
    replaces = [("api_v1", "0002_add_tag_type_to_dictitem")]
    dependencies = [
        ("api_v1", "0005_department_code"),
    ]
    operations = [
        migrations.AddField(
            model_name="dictitem",
            name="tag_type",
            field=models.CharField(max_length=20, blank=True, default=""),
        ),
    ]
