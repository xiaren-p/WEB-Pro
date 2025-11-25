from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api_v1", "0016_crawlercategory"),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='cloud_id',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
    ]
