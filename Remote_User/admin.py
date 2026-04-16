from django.contrib import admin
from .models import ClientRegister_Model, cyber_attack_detection, detection_accuracy, detection_ratio

admin.site.register(ClientRegister_Model)
admin.site.register(cyber_attack_detection)
admin.site.register(detection_accuracy)
admin.site.register(detection_ratio)
