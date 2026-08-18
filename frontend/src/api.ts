import type { Dockyard, Health, Version } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<Health>("/health"),
  version: () => request<Version>("/version"),
  dockyards: () => request<Dockyard[]>("/dockyards"),
  dockyard: (id: number) => request<Dockyard>(`/dockyards/${id}`),
  createDockyard: (name: string, description?: string) =>
    request<Dockyard>("/dockyards", {
      method: "POST",
      body: JSON.stringify({ name, description: description || null }),
    }),
};

