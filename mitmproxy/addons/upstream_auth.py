from mitmproxy.http import HTTPFlow
from mitmproxy import exceptions
from mitmproxy import ctx
from mitmproxy.utils import strutils
from base64 import b64encode


def parse_upstream_auth(username, password):
    if username is None or password is None:
        raise exceptions.OptionsError(
            "Invalid upstream auth specification: %s %s" % username, password)
    return b"Basic" + b" " + b64encode(
        strutils.always_bytes(f"{username}:{password}"))


class UpstreamAuth():
    """
        This addon handles authentication to systems upstream from us for the
        upstream proxy and reverse proxy mode. There are 3 cases:

        - Upstream proxy CONNECT requests should have authentication added, and
          subsequent already connected requests should not.
        - Upstream proxy regular requests
        - Reverse proxy regular requests (CONNECT is invalid in this mode)
    """
    def __init__(self):

        ctx.log.info(
            "\n--------------------------------sessions init--------------------------------\n"
        )

        self.fall_back = ""
        self.zone = ""
        self.password = ""
        self.user_id = ""
        self.country = ""
        self.state = ""
        self.asn = ""
        self.city = ""
        self.session = ""

    def load(self, loader):
        loader.add_option(name="upstream_lum_auth_zone",
                          typespec=str,
                          default='',
                          help="""""")

        loader.add_option(name="upstream_lum_auth_user_id",
                          typespec=str,
                          default='',
                          help="""""")

        loader.add_option(name="upstream_lum_auth_password",
                          typespec=str,
                          default='',
                          help="""""")

        loader.add_option(name="upstream_lum_auth_fall_back",
                          typespec=str,
                          default='',
                          help="""""")

    def configure(self, updated):
        ctx.log.info(
            "\n--------------------------------configure addon--------------------------------\n"
        )

        if "upstream_lum_auth_fall_back" in updated and ctx.options.upstream_lum_auth_fall_back:
            self.fall_back = ctx.options.upstream_lum_auth_fall_back

        if "upstream_lum_auth_zone" in updated and ctx.options.upstream_lum_auth_zone:
            self.zone = ctx.options.upstream_lum_auth_zone

        if "upstream_lum_auth_password" in updated and ctx.options.upstream_lum_auth_password:
            self.password = ctx.options.upstream_lum_auth_password

        if "upstream_lum_auth_user_id" in updated and ctx.options.upstream_lum_auth_user_id:
            self.user_id = ctx.options.upstream_lum_auth_user_id

        if "upstream_lum_country" in updated and ctx.options.upstream_lum_country:
            self.country = f"-country-{str.lower(ctx.options.upstream_lum_country)}"

        if "upstream_lum_state" in updated and ctx.options.upstream_lum_state:
            self.state = f"-state-{str.lower(ctx.options.upstream_lum_state)}"

        if "upstream_lum_asn" in updated and ctx.options.upstream_lum_asn:
            self.asn = f"-state-{ctx.options.upstream_lum_asn}"

        if "upstream_lum_city" in updated and ctx.options.upstream_lum_city:
            self.city = f"-city-{ctx.options.upstream_lum_city}"

        if "upstream_lum_session" in updated and ctx.options.upstream_lum_session:
            self.session = ctx.options.upstream_lum_session

    @property
    def auth(self):
        ctx.log.info(
            "\n--------------------------------authenticate proxy request--------------------------------\n"
        )
        username = f"lum-customer-{self.user_id}-zone-{self.zone}{self.fall_back}{self.country}{self.state}{self.city}{self.asn}-session-{self.session}"
        return parse_upstream_auth(username=username, password=self.password)

    def http_connect(self, f: HTTPFlow):
        ctx.log.info(
            "\n--------------------------------http_connect--------------------------------\n"
        )
        if f.mode == "upstream":
            f.request.headers["Proxy-Authorization"] = self.get_auth(f)

    def requestheaders(self, f: HTTPFlow):
        ctx.log.info(
            "\n--------------------------------requestheaders--------------------------------\n"
        )

        if f.mode == "upstream" and not f.server_conn.via:
            f.request.headers["Proxy-Authorization"] = self.auth
        elif ctx.options.mode.startswith("reverse"):
            f.request.headers["Proxy-Authorization"] = self.auth

    def response(self, f: HTTPFlow):
        """
            The full HTTP response has been read.
        """
        status_code = f.response.status_code
        ctx.log.info(f"status_code: {status_code}")

    def error(self, flow: HTTPFlow):
        """
            An HTTP error has occurred, e.g. invalid server responses, or
            interrupted connections. This is distinct from a valid server HTTP
            error response, which is simply a response with an HTTP error code.
        """
        ctx.log.error(flow.error)