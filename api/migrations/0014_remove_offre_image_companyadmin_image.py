# Generated by Django 4.1.7 on 2023-05-24 11:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_alter_companyadmin_adresse_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='offre',
            name='image',
        ),
        migrations.AddField(
            model_name='companyadmin',
            name='image',
            field=models.ImageField(default='', null=True, upload_to='images/company/'),
        ),
    ]
