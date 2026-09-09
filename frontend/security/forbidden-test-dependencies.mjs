import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const lockfile = JSON.parse(
  await readFile(new URL("../package-lock.json", import.meta.url), "utf8"),
);

for (const packagePath of [
  "node_modules/vitest",
  "node_modules/@vitest/mocker",
]) {
  assert.equal(
    lockfile.packages?.[packagePath],
    undefined,
    `${packagePath} is a forbidden development dependency`,
  );
}

console.log("Forbidden test dependencies are absent.");
