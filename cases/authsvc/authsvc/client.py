"""Tiny HTTP client used to call the user directory."""
import requests

from .tokens import issue_token


def build_session(service_user="authsvc"):
    s = requests.Session()
    s.headers["Authorization"] = "Bearer " + issue_token(service_user, ["service"])
    s.headers["User-Agent"] = "authsvc/1.0"
    return s


def directory_url(base, user_id):
    req = requests.Request("GET", base.rstrip("/") + "/users/" + str(user_id))
    return req.prepare().url
