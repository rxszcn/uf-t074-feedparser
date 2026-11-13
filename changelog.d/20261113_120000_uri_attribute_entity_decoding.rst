Security
--------

*   Clear URI-valued attributes whose decoded value uses a dangerous URI
    scheme.

    Character references in attribute values are now decoded to a stable
    state before the scheme is checked, so values such as
    ``&#106;avascript:...``, ``&amp;#106;avascript:...``, and
    ``javascript&colon;...`` no longer survive sanitization.  The check now
    covers every URI-valued attribute, including form action attributes, on
    HTML, SVG, and MathML elements.  One shared definition of the checked
    attributes lives in ``feedparser.urls``.  Safe values are emitted
    unchanged, including their character references.
