export function formatDate(value: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
    new Date(value),
  );
}

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Turn a machine token such as `denied_out_of_scope` into readable text. */
export function humanize(value: string) {
  return value.replace(/_/g, " ").replace(/^./, (character) => character.toUpperCase());
}

export function plural(count: number, singular: string, many?: string) {
  return `${count} ${count === 1 ? singular : (many ?? `${singular}s`)}`;
}

const KIND_LABELS: Record<string, string> = {
  ipv4: "IPv4 address",
  ipv4_network: "IPv4 network",
  ipv6: "IPv6 address",
  ipv6_network: "IPv6 network",
  hostname: "Hostname",
  url: "HTTP origin",
  host: "Host",
  web: "Web",
};

export function kindLabel(kind: string) {
  return KIND_LABELS[kind] ?? humanize(kind);
}
