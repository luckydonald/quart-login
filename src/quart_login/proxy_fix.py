from werkzeug.middleware.proxy_fix import ProxyFix


class ProxyFixMiddleware(ProxyFix):
    async def __call__(self, scope, receive, send):
        """Modify the WSGI environ based on the various ``Forwarded``
        headers before calling the wrapped application. Store the
        original environ values in ``werkzeug.proxy_fix.orig_{key}``.
        """
        scope_get = scope.get
        orig_remote_addr = scope_get("REMOTE_ADDR")
        orig_wsgi_url_scheme = scope_get("wsgi.url_scheme")
        orig_http_host = scope_get("HTTP_HOST")
        scope.update(
            {
                "werkzeug.proxy_fix.orig": {
                    "REMOTE_ADDR": orig_remote_addr,
                    "wsgi.url_scheme": orig_wsgi_url_scheme,
                    "HTTP_HOST": orig_http_host,
                    "SERVER_NAME": scope_get("SERVER_NAME"),
                    "SERVER_PORT": scope_get("SERVER_PORT"),
                    "SCRIPT_NAME": scope_get("SCRIPT_NAME"),
                }
            }
        )

        x_for = self._get_real_value(self.x_for, scope_get("HTTP_X_FORWARDED_FOR"))
        if x_for:
            scope["REMOTE_ADDR"] = x_for

        x_proto = self._get_real_value(
            self.x_proto, scope_get("HTTP_X_FORWARDED_PROTO")
        )
        if x_proto:
            scope["wsgi.url_scheme"] = x_proto

        x_host = self._get_real_value(self.x_host, scope_get("HTTP_X_FORWARDED_HOST"))
        if x_host:
            scope["HTTP_HOST"] = scope["SERVER_NAME"] = x_host
            # "]" to check for IPv6 address without port
            if ":" in x_host and not x_host.endswith("]"):
                scope["SERVER_NAME"], scope["SERVER_PORT"] = x_host.rsplit(":", 1)

        x_port = self._get_real_value(self.x_port, scope_get("HTTP_X_FORWARDED_PORT"))
        if x_port:
            host = scope.get("HTTP_HOST")
            if host:
                # "]" to check for IPv6 address without port
                if ":" in host and not host.endswith("]"):
                    host = host.rsplit(":", 1)[0]
                scope["HTTP_HOST"] = f"{host}:{x_port}"
            scope["SERVER_PORT"] = x_port

        x_prefix = self._get_real_value(
            self.x_prefix, scope_get("HTTP_X_FORWARDED_PREFIX")
        )
        if x_prefix:
            scope["SCRIPT_NAME"] = x_prefix

        return await self.app(scope, receive, send)
