# Generated by Django 3.2.13 on 2022-04-21 09:02

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Cat',
            fields=[
                ('CatId', models.AutoField(primary_key=True, serialize=False)),
                ('CatName', models.CharField(max_length=100)),
                ('CatFramework', models.CharField(max_length=100)),
                ('CatLang', models.CharField(max_length=100)),
                ('Image', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='response',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('title', models.CharField(max_length=100)),
                ('content', models.TextField()),
                ('author', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='Posts',
            fields=[
                ('pubId', models.AutoField(primary_key=True, serialize=False)),
                ('pubsubject', models.CharField(max_length=255)),
                ('pub', models.CharField(max_length=255)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('cat', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='pub', to='AskApp.cat')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='posts', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Answers',
            fields=[
                ('AnsId', models.AutoField(primary_key=True, serialize=False)),
                ('Ans', models.CharField(max_length=255)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('pubId', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='post', to='AskApp.posts')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='answers', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]