import "whatwg-fetch";
import "@testing-library/jest-dom/jest-globals";

// jsdom does not implement BroadcastChannel. This test double delivers a
// JSON copy to other same-name channels as a microtask, never to itself.
function cloneData(data: unknown): unknown {
  if (data === undefined) return undefined;
  return JSON.parse(JSON.stringify(data)) as unknown;
}

if (typeof globalThis.BroadcastChannel !== "function") {
  const groups = new Map<string, Set<MemoryBroadcastChannel>>();

  class MemoryBroadcastChannel {
    #name: string;
    #closed = false;
    onmessage: ((this: BroadcastChannel, event: MessageEvent) => void) | null = null;

    constructor(name: string) {
      if (typeof name !== "string" || name.length === 0 || name.length > 64) {
        throw new DOMException("Invalid channel name", "SyntaxError");
      }
      this.#name = name;
      let group = groups.get(name);
      if (!group) {
        group = new Set();
        groups.set(name, group);
      }
      group.add(this);
    }

    postMessage(data: unknown): void {
      if (this.#closed) throw new DOMException("Channel is closed", "InvalidStateError");
      const group = groups.get(this.#name);
      if (!group) return;
      for (const peer of group) {
        if (peer === this || peer.#closed || !peer.onmessage) continue;
        const event = { data: cloneData(data) } as MessageEvent;
        queueMicrotask(() => {
          if (!peer.#closed && peer.onmessage) {
            peer.onmessage.call(peer as unknown as BroadcastChannel, event);
          }
        });
      }
    }

    close(): void {
      if (this.#closed) return;
      this.#closed = true;
      this.onmessage = null;
      groups.get(this.#name)?.delete(this);
    }
  }

  globalThis.BroadcastChannel = MemoryBroadcastChannel as unknown as typeof BroadcastChannel;
}
