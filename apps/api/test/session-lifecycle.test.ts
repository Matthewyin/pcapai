import assert from "node:assert/strict";
import test from "node:test";
import { MaxTurnsExceededError } from "@openai/agents";
import { withManagedSession } from "../src/agents/runtime.js";

function fakeSession() {
  let closeCount = 0;
  return {
    session: { close: () => { closeCount += 1; } },
    closeCount: () => closeCount
  };
}

test("持久化 Session 在正常返回后关闭", async () => {
  const fake = fakeSession();
  const result = await withManagedSession(fake.session, async () => "ok");
  assert.equal(result, "ok");
  assert.equal(fake.closeCount(), 1);
});

test("持久化 Session 在异常抛出后关闭", async () => {
  const fake = fakeSession();
  await assert.rejects(() => withManagedSession(fake.session, async () => {
    throw new Error("运行失败");
  }), /运行失败/);
  assert.equal(fake.closeCount(), 1);
});

test("持久化 Session 在 MaxTurnsExceeded 收口返回后关闭", async () => {
  const fake = fakeSession();
  const maxTurnsError = Object.assign(Object.create(MaxTurnsExceededError.prototype), {
    name: "MaxTurnsExceededError",
    message: "max turns exceeded"
  });
  const result = await withManagedSession(fake.session, async () => {
    try {
      throw maxTurnsError;
    } catch (error) {
      if (error instanceof MaxTurnsExceededError) return "已收口";
      throw error;
    }
  });
  assert.equal(result, "已收口");
  assert.equal(fake.closeCount(), 1);
});
