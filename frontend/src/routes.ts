import { useEffect, useState } from "react";

export const pagePaths = {
  Dashboard: "/", Dockyards: "/dockyards", Assets: "/assets", Findings: "/findings",
  RedPath: "/redpath", Intelligence: "/intelligence", Lab: "/lab",
  RedLedger: "/ledger", Reports: "/reports", Settings: "/settings",
} as const;
export type Page = keyof typeof pagePaths;
export const workspaceTabs = [
  "Scope", "Discovery", "Assets", "Services", "Observations", "Detection",
  "Findings", "Validation", "Runs",
] as const;
export type WorkspaceTab = (typeof workspaceTabs)[number];

export type Route = {
  page: Page;
  dockyardId: number | null;
  workspace: boolean;
  tab: WorkspaceTab;
  findingId: number | null;
  unknown: boolean;
};

function identifier(value: string | null): number | null {
  if (!value || !/^[1-9]\d*$/.test(value)) return null;
  const id = Number(value);
  return Number.isSafeInteger(id) ? id : null;
}

export function readRoute(url = new URL(window.location.href)): Route {
  const route: Route = {
    page: "Dashboard", dockyardId: identifier(url.searchParams.get("dockyard")),
    workspace: false, tab: "Scope", findingId: null, unknown: false,
  };
  const path = url.pathname.replace(/\/$/, "") || "/";
  const page = (Object.keys(pagePaths) as Page[]).find((item) => pagePaths[item] === path);
  if (page) return { ...route, page };
  const match = /^\/dockyards\/([^/]+)(?:\/([^/]+))?(?:\/([^/]+))?$/.exec(path);
  if (match) {
    const dockyardId = identifier(match[1]);
    const tab = match[2] ? workspaceTabs.find((item) => item.toLowerCase() === match[2]) : "Scope";
    const findingId = identifier(match[3] ?? null);
    if (dockyardId && tab && (!match[3] || (tab === "Findings" && findingId))) {
      return { ...route, page: "Dockyards", dockyardId, workspace: true, tab, findingId };
    }
  }
  return { ...route, unknown: true };
}

export function pageUrl(page: Page, dockyardId: number | null = null): string {
  return pagePaths[page] + (dockyardId === null ? "" : `?dockyard=${dockyardId}`);
}

export function workspaceUrl(id: number, tab: WorkspaceTab = "Scope", findingId?: number): string {
  return `/dockyards/${id}/${tab.toLowerCase()}` + (findingId === undefined ? "" : `/${findingId}`);
}

export function useRoute() {
  const [route, setRoute] = useState(() => readRoute());
  useEffect(() => {
    const update = () => setRoute(readRoute());
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  function navigate(url: string, replace = false) {
    if (replace) window.history.replaceState(null, "", url);
    else window.history.pushState(null, "", url);
    setRoute(readRoute());
  }
  return { route, navigate };
}
