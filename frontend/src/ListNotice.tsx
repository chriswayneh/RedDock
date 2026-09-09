export function ListNotice({ shown, total, offset = 0 }: { shown: number; total: number | null; offset?: number }) {
  return <p className="hint" role="status">
    Showing {shown}{total === null ? ". Total unavailable." : ` of ${total}.`}
    {total !== null && total > shown && ` This list is limited${shown ? ` to rows ${offset + 1}-${offset + shown}` : ""}.`}
  </p>;
}
