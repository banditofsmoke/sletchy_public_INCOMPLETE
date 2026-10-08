// Everything the views read from Sletchy, and every action they can take.
//
// Each action is one bridge call. After anything that changes state the hook
// re-reads what that change could affect, so the screen never shows a switch, a
// score or a record line that the Kernel no longer agrees with.

import { useCallback, useEffect, useRef, useState } from "react";

import { call, type Outcome } from "../api";
import type {
  FlagView,
  InitResult,
  LedgerTailParams,
  LedgerTailResult,
  PanicResult,
  SelfCheck,
  StatusResult,
} from "../generated/contracts";
import { plainError } from "./plain";
import { toast } from "./store";

export interface SletchyState {
  readonly status: StatusResult | null;
  readonly selfcheck: SelfCheck | null;
  readonly flags: readonly FlagView[];
  readonly ledger: LedgerTailResult | null;
  readonly loading: boolean;
  readonly connection: Outcome<unknown> | null;
}

export interface SletchyActions {
  refresh(): Promise<void>;
  recheck(): Promise<void>;
  setFlag(flag: FlagView, enabled: boolean, reason?: string, confirm?: string): Promise<boolean>;
  setUp(): Promise<void>;
  loadLedger(params: LedgerTailParams): Promise<void>;
  planPanic(): Promise<PanicResult | null>;
  runPanic(): Promise<PanicResult | null>;
}

const DEFAULT_LEDGER: LedgerTailParams = { limit: 50 };

export function useSletchy(): SletchyState & SletchyActions {
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [selfcheck, setSelfcheck] = useState<SelfCheck | null>(null);
  const [flags, setFlags] = useState<readonly FlagView[]>([]);
  const [ledger, setLedger] = useState<LedgerTailResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [connection, setConnection] = useState<Outcome<unknown> | null>(null);
  const ledgerQuery = useRef<LedgerTailParams>(DEFAULT_LEDGER);

  const loadLedger = useCallback(async (params: LedgerTailParams) => {
    ledgerQuery.current = params;
    const out = await call("ledger.tail", params);
    setLedger(out.ok ? out.value : null);
  }, []);

  const reloadStatus = useCallback(async () => {
    const st = await call("status", {});
    setConnection(st);
    setStatus(st.ok ? st.value : null);
  }, []);

  const recheck = useCallback(async () => {
    const out = await call("selfcheck", {});
    if (out.ok) setSelfcheck(out.value);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    const st = await call("status", {});
    setConnection(st);
    setStatus(st.ok ? st.value : null);
    if (st.ok && st.value.ledger_state === "ok") {
      const [fl] = await Promise.all([
        call("flags.list", {}),
        recheck(),
        loadLedger(ledgerQuery.current),
      ]);
      setFlags(fl.ok ? fl.value.flags : []);
    } else {
      setFlags([]);
      setLedger(null);
      await recheck();
    }
    setLoading(false);
  }, [loadLedger, recheck]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const setFlag = useCallback(
    async (flag: FlagView, enabled: boolean, reason = "", confirm = "") => {
      const out = await call("flags.set", { name: flag.name, enabled, reason, confirm });
      if (!out.ok) {
        toast("bad", `${flag.label} was not changed`, plainError(out.code));
        return false;
      }
      setFlags((prev) => prev.map((f) => (f.name === flag.name ? out.value : f)));
      toast(
        enabled && flag.risk === "dangerous" ? "warn" : "good",
        `${flag.label} is ${enabled ? "on" : "off"}`,
        flag.wired ? undefined : "Nothing in Sletchy uses this switch yet, so nothing else changed.",
      );
      // Everything a flip can change: the header pill, the meter, the record.
      await Promise.all([reloadStatus(), recheck(), loadLedger(ledgerQuery.current)]);
      return true;
    },
    [loadLedger, recheck, reloadStatus],
  );

  const setUp = useCallback(async () => {
    const out: Outcome<InitResult> = await call("init", {});
    if (out.ok) toast("good", "Sletchy is set up", out.value.detail);
    else toast("bad", "Setup did not finish", plainError(out.code));
    await refresh();
  }, [refresh]);

  const planPanic = useCallback(async () => {
    const out = await call("stop.plan", {});
    if (!out.ok) toast("bad", "Could not check what Stop everything would do", plainError(out.code));
    return out.ok ? out.value : null;
  }, []);

  const runPanic = useCallback(async () => {
    const out = await call("stop.run", {});
    if (!out.ok) {
      toast("bad", "Stop everything could not run", plainError(out.code));
    } else if (out.value.clean) {
      const kept = out.value.firewall_rules_kept;
      const rules = kept > 0 ? ` Sletchy's ${kept} firewall rules stay: they only stop its own sandboxes reaching other computers.` : "";
      toast("good", "Everything is stopped", `${out.value.flags_reset} switch(es) turned off. Your records are untouched.${rules}`);
    } else {
      toast("warn", "Stopped, with problems", out.value.errors.join(" "));
    }
    await refresh();
    return out.ok ? out.value : null;
  }, [refresh]);

  return {
    status,
    selfcheck,
    flags,
    ledger,
    loading,
    connection,
    refresh,
    recheck,
    setFlag,
    setUp,
    loadLedger,
    planPanic,
    runPanic,
  };
}
