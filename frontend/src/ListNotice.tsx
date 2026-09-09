export function ListNotice({ shown, total, offset = 0 }: { shown: number; total: number | null; offset?: number }) {
  return <p className="hint" role="status">
    {shown > 0 && offset > 0 ? `Showing rows ${offset + 1}-${offset + shown}` : `Showing ${shown}`}
    {total === null ? ". Total unavailable." : ` of ${total}.`}
  </p>;
}

export const PAGE_SIZE = 100;

export function PageControls({
  shown,
  total,
  offset,
  onOffsetChange,
  label = "items",
}: {
  shown: number;
  total: number | null;
  offset: number;
  onOffsetChange: (offset: number) => void;
  label?: string;
}) {
  const hasPrevious = offset > 0;
  const hasNext = total !== null && offset + shown < total && shown > 0;
  return <>
    <ListNotice shown={shown} total={total} offset={offset} />
    {(hasPrevious || hasNext) && <div className="button-row pagination-controls">
      <button disabled={!hasPrevious} onClick={() => onOffsetChange(Math.max(0, offset - PAGE_SIZE))}>
        Previous {label}
      </button>
      <button disabled={!hasNext} onClick={() => onOffsetChange(offset + PAGE_SIZE)}>
        Next {label}
      </button>
    </div>}
  </>;
}
