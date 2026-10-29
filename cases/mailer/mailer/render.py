"""Render transactional emails (written against Jinja2 2.11)."""
from jinja2 import DictLoader, Environment, Markup, contextfilter, escape

TEMPLATES = {
    "welcome.html": "<p>Hi {{ user.name }},</p><p>{{ intro | safe_intro }}</p><p>{{ 'Team' | signed }}</p>",
}


@contextfilter
def signed(ctx, who):
    return Markup("&mdash; {} at {}").format(who, ctx.get("company", "PatchPilot"))


def safe_intro(text):
    return Markup("<em>{}</em>").format(escape(text))


def make_env():
    env = Environment(loader=DictLoader(TEMPLATES), autoescape=True)
    env.filters["signed"] = signed
    env.filters["safe_intro"] = safe_intro
    return env


def render_welcome(name, intro, company="PatchPilot"):
    return make_env().get_template("welcome.html").render(user={"name": name}, intro=intro, company=company)
