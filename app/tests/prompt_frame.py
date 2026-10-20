"""Parse a rendered user prompt the way a trusted consumer would (M7.2).

The boundary token is read only from the first line, which precedes all
untrusted text. Structure is then recognized only by tags carrying that
token, so these helpers count what the prompt actually asserts as trusted
passages and questions - not lines that merely look like them.
"""
import json
import re
from dataclasses import dataclass

FIRST_LINE = re.compile(r"\ARequest boundary: (?P<token>[0-9a-f]{32,})\n")


@dataclass(frozen=True)
class Passage:
    index: int
    source: str
    content: str


@dataclass(frozen=True)
class FramedPrompt:
    token: str
    passages: list[Passage]
    questions: list[str]


def parse_framed_prompt(prompt: str) -> FramedPrompt:
    first = FIRST_LINE.match(prompt)
    if first is None:
        raise ValueError("prompt does not start with a boundary declaration")
    token = re.escape(first.group("token"))
    passage = re.compile(
        rf'<passage-{token} index="(?P<index>\d+)" source=(?P<source>"(?:[^"\\\n]|\\.)*")>\n'
        rf"(?P<content>.*?)\n</passage-{token}>",
        re.S,
    )
    question = re.compile(rf"<question-{token}>\n(?P<q>.*?)\n</question-{token}>", re.S)
    return FramedPrompt(
        token=first.group("token"),
        passages=[
            Passage(int(m.group("index")), json.loads(m.group("source")), m.group("content"))
            for m in passage.finditer(prompt)
        ],
        questions=[m.group("q") for m in question.finditer(prompt)],
    )
