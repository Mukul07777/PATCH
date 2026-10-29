"""Sanitize user comments before rendering (written against bleach 3.x)."""
import bleach

TAGS = ["a", "b", "i", "em", "strong", "code", "p", "span", "ul", "li"]
ATTRS = {"a": ["href", "title"], "span": ["style"]}
STYLES = ["color", "font-weight"]


def clean_comment(html):
    return bleach.clean(html, tags=TAGS, attributes=ATTRS, styles=STYLES, strip=True)


def linkify_comment(html):
    return bleach.linkify(clean_comment(html))


def plain_text(html):
    return bleach.clean(html, tags=[], strip=True)
