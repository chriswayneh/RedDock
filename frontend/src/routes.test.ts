import { describe, expect, it } from "vitest";
import { pagePaths, readRoute, workspaceTabs, workspaceUrl } from "./routes";

describe("client URL parser", () => {
  it("supports every page and workspace tab", () => {
    for (const [page, path] of Object.entries(pagePaths)) {
      expect(readRoute(new URL(path, "http://localhost")).page).toBe(page);
    }
    for (const tab of workspaceTabs) {
      expect(readRoute(new URL(workspaceUrl(9, tab), "http://localhost"))).toMatchObject({ dockyardId: 9, tab, workspace: true, unknown: false });
    }
    expect(readRoute(new URL("http://localhost/dockyards/9"))).toMatchObject({ tab: "Scope", workspace: true });
  });
  it.each(["/dockyards/0", "/dockyards/-1", "/dockyards/9007199254740992", "/dockyards/1/nope", "/dockyards/1/assets/2", "/dockyards/1/findings/nope", "/nope"])("recovers safely from %s", (path) => {
    expect(readRoute(new URL(path, "http://localhost"))).toMatchObject({ page: "Dashboard", unknown: true });
  });
});
