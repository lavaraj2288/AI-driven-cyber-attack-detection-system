from django.http import HttpResponseForbidden
from Service_Provider.models import BlockedIP

class BlockedIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        
        # Bypass blocking for admin status checks if needed, 
        # but the request asks for "Check before every request"
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("🚫 Your IP is permanently blocked due to suspicious activity. Contact administrator.")
        
        response = self.get_response(request)
        return response
