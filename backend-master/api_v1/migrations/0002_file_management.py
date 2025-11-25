from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('api_v1', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FileEntry',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=255)),
                ('is_folder', models.BooleanField(default=False)),
                ('url', models.CharField(blank=True, default='', max_length=255)),
                ('size', models.BigIntegerField(default=0)),
                ('content_type', models.CharField(blank=True, default='', max_length=100)),
                ('is_deleted', models.BooleanField(default=False)),
                ('deleted_at', models.DateTimeField(blank=True, null=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='file_entries', to=settings.AUTH_USER_MODEL)),
                ('parent', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='children', to='api_v1.fileentry')),
            ],
            options={
                'verbose_name': '文件条目',
                'verbose_name_plural': '文件条目',
            },
        ),
        migrations.CreateModel(
            name='FileShare',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('token', models.CharField(max_length=64, unique=True)),
                ('password', models.CharField(blank=True, default='', max_length=32)),
                ('scope', models.CharField(default='public', max_length=20)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('allowed_users', models.ManyToManyField(blank=True, related_name='file_shares', to=settings.AUTH_USER_MODEL)),
                ('creator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_shares', to=settings.AUTH_USER_MODEL)),
                ('entry', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shares', to='api_v1.fileentry')),
            ],
            options={
                'verbose_name': '文件分享',
                'verbose_name_plural': '文件分享',
            },
        ),
        migrations.AddIndex(
            model_name='fileentry',
            index=models.Index(fields=['owner', 'is_deleted'], name='api_v1_file_owner__is_d7b3f3_idx'),
        ),
        migrations.AddIndex(
            model_name='fileentry',
            index=models.Index(fields=['parent', 'is_deleted'], name='api_v1_file_parent__is_5a0d69_idx'),
        ),
        migrations.AddIndex(
            model_name='fileshare',
            index=models.Index(fields=['token'], name='api_v1_file_token_94d8bc_idx'),
        ),
    ]
