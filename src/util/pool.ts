// Run async tasks with a concurrency limit. Used to pace each provider to its subscription quota:
// the Claude hunters share one pool, the Codex agents share another, both run in parallel.
export async function runLimited<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let next = 0;
  const n = Math.max(1, Math.min(limit, tasks.length || 1));
  const worker = async (): Promise<void> => {
    for (;;) {
      const idx = next++;
      if (idx >= tasks.length) return;
      results[idx] = await tasks[idx]();
    }
  };
  await Promise.all(Array.from({ length: n }, worker));
  return results;
}
