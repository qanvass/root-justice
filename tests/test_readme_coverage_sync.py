"""Keep the README defense-coverage table in sync with coverage.py.

`artex_antidote/coverage.py` is the single source of truth for the defense
coverage matrix, and `README.md` carries a hand-copied Markdown render of the
same table. This test parses the table out of the README and asserts it equals
`coverage.render_markdown()`, so drift between the two fails CI.

Offline and deterministic: the only I/O is reading the repository's own
README.md.
"""

from __future__ import annotations

import os
import unittest

from artex_antidote.coverage import render_markdown

README_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"
)
SECTION_HEADING = "## Defense coverage"


def readme_coverage_table() -> str:
    """Return the Markdown table under the defense-coverage heading.

    The table is the first contiguous block of lines starting with ``|``
    after the section heading. Raises AssertionError if there is no such
    table, so a restructured README fails loudly instead of passing vacuously.
    """
    with open(README_PATH, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    start = next(
        (i for i, line in enumerate(lines)
         if line.startswith(SECTION_HEADING)),
        None,
    )
    if start is None:
        raise AssertionError(
            "README.md has no %r section" % SECTION_HEADING
        )
    table_lines = []
    in_table = False
    for line in lines[start + 1:]:
        if line.startswith("|"):
            table_lines.append(line.rstrip())
            in_table = True
        elif in_table:
            break
    if not table_lines:
        raise AssertionError(
            "README.md %r section contains no Markdown table"
            % SECTION_HEADING
        )
    return "\n".join(table_lines)


class TestReadmeCoverageSync(unittest.TestCase):
    """The README table must equal the rendered source of truth."""

    def test_readme_table_matches_render_markdown(self) -> None:
        self.assertEqual(readme_coverage_table(), render_markdown())


if __name__ == "__main__":
    unittest.main()
