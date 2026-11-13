"""Regression tests for entity-encoded and form-action URI attributes.

These tests cover the two ways dangerous content previously escaped the
sanitizer:

1.  A dangerous scheme hidden behind character references in an ``href`` (or
    any other URI-valued attribute) survived sanitization, because only the raw
    attribute value was checked.  A renderer decodes the references and then
    runs the scheme, so ``&#106;avascript:`` and its doubly-encoded variants
    must be rejected.

2.  Form action attributes (``action``, ``formaction``) were never checked at
    all, so ``<form action="javascript:...">`` was emitted unchanged.

The parametrization deliberately crosses three axes: the encoding variant,
the element type, and the attribute type.
"""

from __future__ import annotations

import pytest

import feedparser.sanitizer
import feedparser.urls


BASE_URI = "http://d.test/d/f.ext"


def sanitize(html: str) -> str:
    return feedparser.sanitizer.sanitize_html(html, None, "text/html")


# (label, encoded value that resolves to `javascript:alert(1)`)
DANGEROUS_ENCODINGS = (
    ("plain", "javascript:alert(1)"),
    ("mixed case", "JaVaScRiPt:alert(1)"),
    ("decimal reference", "&#106;avascript:alert(1)"),
    ("hex lowercase reference", "&#x6a;avascript:alert(1)"),
    ("hex uppercase reference", "&#X6A;avascript:alert(1)"),
    ("zero padded reference", "&#0000106;avascript:alert(1)"),
    (
        "fully referenced scheme",
        "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;"
        "alert(1)",
    ),
    ("referenced colon", "javascript&#58;alert(1)"),
    ("named colon entity", "javascript&colon;alert(1)"),
    ("referenced tab", "java&#9;script:alert(1)"),
    ("tab entity", "java&Tab;script:alert(1)"),
    ("referenced newline", "jav&#x0a;ascript:alert(1)"),
    ("double encoded (named amp)", "&amp;#106;avascript:alert(1)"),
    ("double encoded (numeric amp)", "&#38;#106;avascript:alert(1)"),
    ("triple encoded", "&amp;amp;#106;avascript:alert(1)"),
    ("double encoded colon", "javascript&amp;colon;alert(1)"),
    ("vbscript", "vbscript:msgbox(1)"),
    ("vbscript encoded", "&#118;bscript:msgbox(1)"),
    ("data uri", "data:text/html,<script>alert(1)</script>"),
    ("data uri encoded", "&#100;ata:text/html,alert(1)"),
)

# (element type, element that carries the attribute, attribute name)
URI_ATTRIBUTE_CASES = (
    ("anchor", "<a {attr}=...>link</a>", "href"),
    ("area", '<map><area {attr}=... /></map>', "href"),
    ("image", "<img {attr}=... />", "src"),
    ("old image lowsrc", "<img {attr}=... />", "lowsrc"),
    ("old image dynsrc", "<img {attr}=... />", "dynsrc"),
    ("input", "<input {attr}=... />", "src"),
    ("source", "<audio><source {attr}=... /></audio>", "src"),
    ("video poster", "<video {attr}=...></video>", "poster"),
    ("blockquote", "<blockquote {attr}=...>quote</blockquote>", "cite"),
    ("quote", "<q {attr}=...>quote</q>", "cite"),
    ("deletion", "<del {attr}=...>text</del>", "cite"),
    ("insertion", "<ins {attr}=...>text</ins>", "cite"),
    ("table background", "<table {attr}=...><tr><td>x</td></tr></table>", "background"),
    ("image longdesc", "<img {attr}=... />", "longdesc"),
    ("image usemap", "<img {attr}=... />", "usemap"),
    ("anchor ping", "<a {attr}=...>link</a>", "ping"),
    ("form action", "<form {attr}=...><input /></form>", "action"),
    ("span action", "<span {attr}=...>x</span>", "action"),
)

FORM_ACTION_CASES = (
    ("form action", "<form {attr}=...><input /></form>", "action"),
    ("span action", "<span {attr}=...>x</span>", "action"),
)


def _render_attr(attribute: str, value: str) -> str:
    return value  # keep helpers explicit; templates format the attribute name


@pytest.mark.parametrize(
    "label, element_template, attribute",
    URI_ATTRIBUTE_CASES,
    ids=[case[0] for case in URI_ATTRIBUTE_CASES],
)
@pytest.mark.parametrize(
    "encoding_label, encoded_value",
    DANGEROUS_ENCODINGS,
    ids=[case[0] for case in DANGEROUS_ENCODINGS],
)
def test_dangerous_scheme_is_cleared_in_every_uri_attribute(
    label, element_template, attribute, encoding_label, encoded_value
):
    """A dangerous scheme must be cleared regardless of encoding or element."""

    html = element_template.format(attr=f'{attribute}="{encoded_value}"')
    result = sanitize(html)

    assert f'{attribute}=""' in result
    assert "javascript" not in result.lower()
    assert "vbscript" not in result.lower()
    assert "&#106;" not in result
    assert "data:" not in result.lower()


@pytest.mark.parametrize(
    "label, element_template, attribute",
    URI_ATTRIBUTE_CASES,
    ids=[case[0] for case in URI_ATTRIBUTE_CASES],
)
def test_safe_scheme_is_preserved_in_every_uri_attribute(
    label, element_template, attribute
):
    """Safe schemes and relative references must not be modified."""

    for safe_value in (
        "https://example.test/a",
        "http://example.test/a?b=1&amp;c=2",
        "/relative/path",
        "relative.html",
        "#fragment",
        "mailto:someone@example.test",
        "magnet:?xt=urn:btih:1234",
    ):
        html = element_template.format(attr=f'{attribute}="{safe_value}"')
        result = sanitize(html)
        assert f'{attribute}="{safe_value}"' in result, (html, result)


@pytest.mark.parametrize(
    "label, element_template, attribute",
    URI_ATTRIBUTE_CASES,
    ids=[case[0] for case in URI_ATTRIBUTE_CASES],
)
def test_entity_encoded_safe_scheme_keeps_its_encoded_form(
    label, element_template, attribute
):
    """Safe values keep their character references: output does not regress."""

    for encoded_value in (
        "&#104;ttp://example.test/a",
        "http://example.test/?a=1&amp;b=2",
        "&#x68;ttps://example.test/",
    ):
        html = element_template.format(attr=f'{attribute}="{encoded_value}"')
        result = sanitize(html)
        assert f'{attribute}="{encoded_value}"' in result, (html, result)


@pytest.mark.parametrize(
    "label, element_template, attribute",
    FORM_ACTION_CASES,
    ids=[case[0] for case in FORM_ACTION_CASES],
)
def test_form_action_is_checked(label, element_template, attribute):
    """Form action attributes are checked even when not encoded."""

    html = element_template.format(attr=f'{attribute}="javascript:alert(1)"')
    assert f'{attribute}=""' in sanitize(html)

    html = element_template.format(attr=f'{attribute}="http://example.test/x"')
    assert f'{attribute}="http://example.test/x"' in sanitize(html)


@pytest.mark.parametrize(
    "encoded_value",
    (
        "&#106;avascript:alert(1)",
        "&#106;avascript:1 http://ok.test/",
        "http://ok.test/ &#106;avascript:1",
    ),
)
def test_ping_list_items_are_all_checked(encoded_value):
    result = sanitize(f'<a ping="{encoded_value}">link</a>')
    assert 'ping=""' in result
    assert "javascript" not in result.lower()


def test_svg_and_mathml_uri_attributes_are_checked():
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<a xlink:href="&#106;avascript:alert(1)">x</a></svg>'
    )
    assert 'xlink:href=""' in sanitize(svg)

    mathml = (
        '<math xmlns="http://www.w3.org/1998/Math/MathML">'
        '<maction href="&#106;avascript:alert(1)">x</maction></math>'
    )
    assert 'href=""' in sanitize(mathml)


def test_decoded_output_is_not_written_back():
    """The decoded value is only inspected; the emitted value is unchanged.

    Writing the decoded value back would silently rewrite all safe content
    that legitimately uses character references (for example ``&amp;`` in query
    strings), which is a behavior change for existing consumers.
    """

    html = '<a href="&#104;ttp://example.test/a?x=1&amp;y=2">link</a>'
    assert sanitize(html) == html


def test_uri_attribute_set_is_defined_in_one_place():
    """The sanitizer and the relative URI resolver share one definition."""

    assert feedparser.urls.URI_ATTRIBUTES is not None
    assert "href" in feedparser.urls.URI_ATTRIBUTES
    assert "action" in feedparser.urls.URI_ATTRIBUTES
    assert feedparser.urls.FORM_ACTION_ATTRIBUTES <= feedparser.urls.URI_ATTRIBUTES
    assert feedparser.urls.SEPARATED_URI_ATTRIBUTES <= feedparser.urls.URI_ATTRIBUTES

    # Every URI attribute the sanitizer can emit is checked by the shared
    # helper, even if it is not on the attribute whitelist today.
    assert feedparser.urls.make_safe_uri("formaction", "javascript:alert(1)") == ""
    assert (
        feedparser.urls.make_safe_uri("formaction", "http://example.test/")
        == "http://example.test/"
    )


def test_decode_stops_at_a_stable_state():
    assert feedparser.urls.decode_entity_encoded_value("plain") == "plain"
    # Each round removes one layer of encoding; decoding continues until the
    # value no longer changes, so a doubly-encoded reference becomes the
    # character a renderer would eventually see.
    assert feedparser.urls.decode_entity_encoded_value("&amp;amp;x") == "&x"
    assert feedparser.urls.decode_entity_encoded_value("&amp;amp;#106;") == "j"
    # A value whose nesting exceeds the decode budget is rejected rather than
    # decoded forever.
    depth = feedparser.urls.ENTITY_DECODE_MAX_ROUNDS + 1
    too_deep = "&" + "amp;" * depth + "x"
    assert feedparser.urls.decode_entity_encoded_value(too_deep) is None


def test_unacceptable_schemes_can_still_be_allowed_via_the_whitelist(monkeypatch):
    """The shared check honours the module-level scheme whitelist."""

    monkeypatch.setattr(feedparser.urls, "ACCEPTABLE_URI_SCHEMES", ())
    assert feedparser.urls.make_safe_uri("href", "javascript:alert(1)") == (
        "javascript:alert(1)"
    )


# ----- relative URI resolution -----

RELATIVE_RESOLVER_CASES = (
    '<a href="&#106;avascript:alert(1)">x</a>',
    '<a href="&amp;#106;avascript:alert(1)">x</a>',
    '<a href="javascript&colon;alert(1)">x</a>',
    '<form action="&#106;avascript:alert(1)">x</form>',
    '<img src="&#106;avascript:alert(1)" />',
    '<blockquote cite="&#106;avascript:alert(1)">x</blockquote>',
)


@pytest.mark.parametrize("html", RELATIVE_RESOLVER_CASES)
def test_relative_resolver_checks_the_decoded_value(html):
    result = feedparser.urls.resolve_relative_uris(
        html, BASE_URI, None, "text/html"
    )
    assert '=""' in result
    assert "javascript" not in result.lower()


def test_relative_resolver_still_resolves_relative_uris():
    result = feedparser.urls.resolve_relative_uris(
        '<a href="/doc">x</a>', BASE_URI, None, "text/html"
    )
    assert result == '<a href="http://d.test/doc">x</a>'

    result = feedparser.urls.resolve_relative_uris(
        '<a href="http://ok.test/?a=1&amp;b=2">x</a>', BASE_URI, None, "text/html"
    )
    assert result == '<a href="http://ok.test/?a=1&amp;b=2">x</a>'


def test_full_pipeline_clears_encoded_href_and_form_action():
    xml = (
        '<feed xmlns="http://www.w3.org/2005/Atom">'
        '<title type="html">&lt;a href="&amp;#106;avascript:alert(1)"&gt;'
        "safe&lt;/a&gt;</title>"
        '<entry><content type="html">'
        '&lt;form action="&amp;#106;avascript:alert(1)"&gt;'
        '&lt;input name="q" /&gt;&lt;/form&gt;'
        "</content></entry>"
        "</feed>"
    )
    result = feedparser.parse(xml)
    assert result["bozo"] is False
    assert result.feed["title_detail"]["value"] == '<a href="">safe</a>'
    assert result.entries[0]["content"][0]["value"] == (
        '<form action=""><input name="q" /></form>'
    )
