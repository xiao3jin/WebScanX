import json

from django.db import models

# Create your models here.

class ManUser(models.Model):
    uname = models.CharField(max_length=255)
    upwd = models.CharField(max_length=255)

class Users(models.Model):
    uname = models.CharField(max_length=255)
    upwd = models.CharField(max_length=255)
    status = models.IntegerField(default=1)
    create_time = models.CharField(max_length=255)

class Fingers(models.Model):
    cmsname = models.CharField(max_length=255)
    keyword =models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    method = models.CharField(max_length=255)

class Finger_type(models.Model):
    name = models.CharField(max_length=255)

# class ScanTask(models.Model):
#     STATUS_CHOICES = (
#         ('pending', 'Pending'),
#         ('running', 'Running'),
#         ('completed', 'Completed'),
#         ('failed', 'Failed'),
#     )
#     target = models.CharField(max_length=255)
#     selected_scans = models.TextField()  # 使用 TextField 存储 JSON
#     port_scan_ports = models.CharField(max_length=255, blank=True, null=True)
#     nuclei_option = models.CharField(max_length=50, blank=True, null=True)
#     nuclei_custom_pocs = models.TextField(blank=True, null=True)
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
#     results = models.TextField(blank=True, null=True)  # 使用 TextField 存储 JSON
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#
#     def set_selected_scans(self, scans):
#         self.selected_scans = json.dumps(scans)
#
#     def get_selected_scans(self):
#         return json.loads(self.selected_scans)
#
#     def set_results(self, results):
#         self.results = json.dumps(results)
#
#     def get_results(self):
#         return json.loads(self.results) if self.results else None
#
#     def __str__(self):
#         return f"Scan for {self.target} - {self.status}"