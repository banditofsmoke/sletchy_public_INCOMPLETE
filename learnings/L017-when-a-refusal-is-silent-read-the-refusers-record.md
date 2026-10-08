# L017 - When a refusal is silent, read the refuser's own record

**2026-10-04 to 2026-10-05, #71: three rounds of a probe that could not see UDP.**

## What happened

The egress probe sent UDP from inside a sandbox to an address reserved for documentation,
which never answers. Every UDP row, in every round, timed out with no error: with no
lock, with the container's own lock, with the rules, with neither. The first version
printed *"went out and timed out: NOT stopped"*, which it could not know (ADR-0006 finding
7). The next printed the honest version: *"a dropped datagram and an unanswered one look
the same"*. Two more rounds could not get past it.

On 2026-10-05 the operator read Windows' own drop log as administrator (`netsh wfp show
netevents`, read-only, buffered by default). It named the filter behind every drop: the
container's default block dropped each UDP datagram, and with the container's lock opened,
the lane's own rule did (finding 9). The answer had been on the machine all along.

## Why it happened

The probe could only ask the program it ran what happened, and a firewall that drops a
datagram tells its sender nothing: `sendto` succeeds, and the packet never leaves. From
the sender's side a silent refusal and an unanswered success are identical, by design. No
number of rounds measured from that side could have told them apart.

## The rule

- **A probe that reads only what the refused program was told cannot measure a control
  that refuses silently.** Read the control's own record: here, the Windows Filtering
  Platform's drop log, which names the filter
- **Match each record to a probe row by something both print**: here, the local port curl
  reports and the time. A record matched to nothing proves nothing
- **A control row must have no record.** Here, the container no rule names: with no drop
  logged against it, the drops against the lane are the rule's, not the machine's
- **Silence on the sender's side is "could not see" (L009), never "went through"**
