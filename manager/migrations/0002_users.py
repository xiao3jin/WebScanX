# Generated by Django 2.2.17 on 2024-09-13 08:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('manager', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Users',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uname', models.CharField(max_length=255)),
                ('upwd', models.CharField(max_length=255)),
                ('status', models.IntegerField(default=1)),
                ('create_time', models.CharField(max_length=255)),
            ],
        ),
    ]
