from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='gender',
            field=models.IntegerField(default=0, help_text='0=保密,1=男,2=女'),
        ),
    ]
