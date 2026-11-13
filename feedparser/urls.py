# Copyright 2010-2025 Kurt McKee <contactme@kurtmckee.org>
# Copyright 2002-2008 Mark Pilgrim
# All rights reserved.
#
# This file is a part of feedparser.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import html
import re
import urllib.parse

from .html import BaseHTMLProcessor

# If you want feedparser to allow all URL schemes, set this to ()
# List culled from Python's urlparse documentation at:
#   http://docs.python.org/library/urlparse.html
# as well as from "URI scheme" at Wikipedia:
#   https://secure.wikimedia.org/wikipedia/en/wiki/URI_scheme
# Many more will likely need to be added!
ACCEPTABLE_URI_SCHEMES = (
    "file",
    "ftp",
    "gopher",
    "h323",
    "hdl",
    "http",
    "https",
    "imap",
    "magnet",
    "mailto",
    "mms",
    "news",
    "nntp",
    "prospero",
    "rsync",
    "rtsp",
    "rtspu",
    "sftp",
    "shttp",
    "sip",
    "sips",
    "snews",
    "svn",
    "svn+ssh",
    "telnet",
    "wais",
    # Additional common-but-unofficial schemes
    "aim",
    "callto",
    "cvs",
    "facetime",
    "feed",
    "git",
    "gtalk",
    "irc",
    "ircs",
    "irc6",
    "itms",
    "mms",
    "msnim",
    "skype",
    "ssh",
    "smb",
    "svn",
    "ymsg",
)

_urifixer = re.compile("^([A-Za-z][A-Za-z0-9+-.]*://)(/*)(.*?)")


# Form action attributes submit data to a URI.  They are listed separately so
# that it is obvious that *every* one of them is checked, including attributes
# that a future change may add to the attribute whitelist.
FORM_ACTION_ATTRIBUTES = frozenset(
    {
        "action",
        "formaction",
    }
)

# Attributes whose value is a URI (or a URI reference), grouped by the element
# semantics that give the attribute its URI meaning.  Renderers decode
# character references in attribute values before interpreting them, so every
# URI attribute must be validated on its decoded form.  This set is defined
# here, in one place next to the scheme whitelist, so the sanitizer and the
# relative URI resolver cannot drift apart.
URI_ATTRIBUTES = (
    frozenset(
        {
            # Navigation and links: a, area, link, blockquote, q, del, ins,
            # img, iframe, frame, and the SVG a element.
            "href",
            "xlink:href",
            "cite",
            "longdesc",
            "usemap",
            "xml:base",
            # Embedded or fetched resources: img, input, source, audio, video,
            # object, command, body, table, td, th, tr.
            "src",
            "lowsrc",
            "dynsrc",
            "background",
            "poster",
            "data",
            "datasrc",
            "codebase",
            "classid",
            "icon",
            # Document-level metadata: head profile, html manifest.
            "profile",
            "manifest",
            # Notification endpoints: a ping, area ping.
            "ping",
            # MathML: maction/math href and mrow altimg.
            "altimg",
        }
    )
    | FORM_ACTION_ATTRIBUTES
)

# Attributes that hold a whitespace-separated list of URIs.  A renderer
# splits the value after decoding it, so every item is validated separately.
SEPARATED_URI_ATTRIBUTES = frozenset({"ping"})

# Character references can be nested (`&amp;#106;avascript:`).  Values are
# decoded to a stable state so a second encoding cannot hide a scheme.
# The bound guarantees termination; a value that does not stabilize within
# the bound is treated as unsafe.
ENTITY_DECODE_MAX_ROUNDS = 8


def decode_entity_encoded_value(value: str) -> str | None:
    """Decode character references until the value reaches a stable state.

    Nested encodings are decoded round after round, matching what a renderer
    does when it decodes an attribute value more than once.  Returns ``None``
    when the value does not stabilize within
    :data:`ENTITY_DECODE_MAX_ROUNDS` rounds; callers must treat that as unsafe.
    """

    for _ in range(ENTITY_DECODE_MAX_ROUNDS):
        decoded = html.unescape(value)
        if decoded == value:
            return value
        value = decoded
    return None


def uri_scheme_is_acceptable(value: str) -> bool:
    """Return ``True`` if *value* uses no scheme or an acceptable scheme."""

    if not ACCEPTABLE_URI_SCHEMES:
        return True
    try:
        scheme = urllib.parse.urlparse(value)[0]
    except ValueError:
        return False
    return not scheme or scheme in ACCEPTABLE_URI_SCHEMES


def make_safe_uri(attribute: str, value: str) -> str:
    """Validate a URI-valued attribute and clear it if its scheme is unsafe.

    The value is decoded to a stable state first, then every URI it contains
    (one, or several for list-valued attributes such as ``ping``) is checked
    against :data:`ACCEPTABLE_URI_SCHEMES`.

    The *original* value is returned when it is acceptable.  The decoded form
    is used only for inspection, so the sanitizer's output for safe content
    keeps its existing escaping and character references unchanged.  An empty
    string is returned when a dangerous scheme is found, which clears the
    attribute value.
    """

    if not value:
        return value
    decoded = decode_entity_encoded_value(value)
    if decoded is None:
        return ""
    if attribute in SEPARATED_URI_ATTRIBUTES:
        candidates = decoded.split()
    else:
        candidates = [decoded]
    if all(uri_scheme_is_acceptable(candidate) for candidate in candidates):
        return value
    return ""


def _urljoin(base, uri):
    uri = _urifixer.sub(r"\1\3", uri)
    try:
        uri = urllib.parse.urljoin(base, uri)
    except ValueError:
        uri = ""
    return uri


def make_safe_absolute_uri(base, rel=None):
    # bail if ACCEPTABLE_URI_SCHEMES is empty
    if not ACCEPTABLE_URI_SCHEMES:
        return _urljoin(base, rel or "")
    if not base:
        return rel or ""
    if not rel:
        try:
            scheme = urllib.parse.urlparse(base)[0]
        except ValueError:
            return ""
        if not scheme or scheme in ACCEPTABLE_URI_SCHEMES:
            return base
        return ""
    uri = _urljoin(base, rel)
    if uri.strip().split(":", 1)[0] not in ACCEPTABLE_URI_SCHEMES:
        return ""
    return uri


class RelativeURIResolver(BaseHTMLProcessor):
    relative_uris = {
        ("a", "href"),
        ("applet", "codebase"),
        ("area", "href"),
        ("audio", "src"),
        ("blockquote", "cite"),
        ("body", "background"),
        ("del", "cite"),
        ("form", "action"),
        ("frame", "longdesc"),
        ("frame", "src"),
        ("iframe", "longdesc"),
        ("iframe", "src"),
        ("head", "profile"),
        ("img", "longdesc"),
        ("img", "src"),
        ("img", "usemap"),
        ("input", "src"),
        ("input", "usemap"),
        ("ins", "cite"),
        ("link", "href"),
        ("object", "classid"),
        ("object", "codebase"),
        ("object", "data"),
        ("object", "usemap"),
        ("q", "cite"),
        ("script", "src"),
        ("source", "src"),
        ("video", "poster"),
        ("video", "src"),
    }

    def __init__(self, baseuri, encoding, _type):
        BaseHTMLProcessor.__init__(self, encoding, _type)
        self.baseuri = baseuri

    def resolve_uri(self, uri):
        """Resolve *uri* against the base URI, after checking its scheme.

        The scheme check runs on the decoded value so that character
        references cannot hide a dangerous scheme from this pass; the URI that
        is resolved and emitted is otherwise unchanged.
        """

        uri = uri.strip()
        decoded = decode_entity_encoded_value(uri)
        if decoded is None:
            return ""
        if uri_scheme_is_acceptable(decoded):
            return make_safe_absolute_uri(self.baseuri, uri)
        return ""

    def unknown_starttag(self, tag, attrs):
        attrs = self.normalize_attrs(attrs)
        resolved = []
        for key, value in attrs:
            if (tag, key) in self.relative_uris:
                # Resolution re-checks the decoded value (see resolve_uri).
                value = self.resolve_uri(value)
            elif key in URI_ATTRIBUTES:
                # Not resolved, but still validated on its decoded value so
                # that this pass and the sanitizer use the same rule.
                value = make_safe_uri(key, value)
            resolved.append((key, value))
        super().unknown_starttag(tag, resolved)


def resolve_relative_uris(html_source, base_uri, encoding, type_):
    p = RelativeURIResolver(base_uri, encoding, type_)
    p.feed(html_source)
    return p.output()
