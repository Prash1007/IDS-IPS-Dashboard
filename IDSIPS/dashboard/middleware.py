from django.conf import settings


class SecurityHeadersMiddleware:
    """Adds project-level browser hardening headers without changing views."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if getattr(settings, "CONTENT_SECURITY_POLICY", ""):
            response.setdefault("Content-Security-Policy", settings.CONTENT_SECURITY_POLICY)
        if getattr(settings, "PERMISSIONS_POLICY", ""):
            response.setdefault("Permissions-Policy", settings.PERMISSIONS_POLICY)
        if getattr(settings, "CROSS_ORIGIN_OPENER_POLICY", ""):
            response.setdefault("Cross-Origin-Opener-Policy", settings.CROSS_ORIGIN_OPENER_POLICY)
        return response
