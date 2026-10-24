/**
 * The verdict a verdicts/<finding>.md file DECLARES: the first `VERDICT:` token in it, uppercased.
 *
 * It lives in its own module so the validator, the reporter, the pending-work scan and the watchdog all
 * read a verdict the same way. Two of them disagreeing is not hypothetical: testing the whole file once
 * per outcome (`/VERDICT:\s*SKIPPED/.test(body)`) matched a VALID verdict whose body happens to carry
 * "VERDICT:" at the end of one line and "SKIPPED" at the start of the next, because JS `\s*` crosses the
 * newline where a line-based grep does not. That dropped a payable saudiacargo finding from the count.
 */
export function verdictOf(content: string): string {
  return (content.match(/VERDICT:\s*([A-Za-z-]+)/i)?.[1] ?? "").toUpperCase();
}

/** A verdict file that carries one of these has been decided; anything else still needs the validator. */
export const DECIDED = new Set(["VALID", "INVALID", "NEEDS-FIX", "SKIPPED"]);
