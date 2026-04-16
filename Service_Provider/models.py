from django.db import models

# Create your models here.

class AttackLog(models.Model):
    ip_address = models.CharField(max_length=50)
    action = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    is_alert = models.BooleanField(default=False)
    country = models.CharField(max_length=50, default='Unknown')
    city = models.CharField(max_length=50, default='Unknown')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.attack_type} - {self.timestamp}"

class BlockedIP(models.Model):
    ip_address = models.CharField(max_length=50, unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
