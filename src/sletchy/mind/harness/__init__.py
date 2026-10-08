"""The harness: one stream of events per conversation turn, hosts that only translate it.

[ADR-0018](../../../../docs/adr/0018-the-harness-one-stream-per-turn-every-event-on-the-record.md).
"""

from sletchy.mind.harness.executor import ANSWER_SHARE, CHARS_PER_TOKEN, ERROR_ACTION, Conversation

__all__ = ["ANSWER_SHARE", "CHARS_PER_TOKEN", "ERROR_ACTION", "Conversation"]
