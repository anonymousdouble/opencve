# Generated by Django 4.2.3 on 2023-11-11 08:19

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("organizations", "0007_membership_email_alter_membership_role"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="membership",
            name="email",
        ),
    ]
