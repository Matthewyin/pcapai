const caseRunLocks = new Map<string, Promise<unknown>>();

export function withCaseRunLock<T>(caseId: string, task: () => T | Promise<T>): Promise<T> {
  const previous = caseRunLocks.get(caseId) || Promise.resolve();
  const next = previous.then(task, task);
  caseRunLocks.set(caseId, next);
  next.then(
    () => {
      if (caseRunLocks.get(caseId) === next) caseRunLocks.delete(caseId);
    },
    () => {
      if (caseRunLocks.get(caseId) === next) caseRunLocks.delete(caseId);
    }
  );
  return next;
}

export const caseRunLockTestHooks = {
  activeCaseCount: () => caseRunLocks.size,
  reset: () => caseRunLocks.clear()
};
