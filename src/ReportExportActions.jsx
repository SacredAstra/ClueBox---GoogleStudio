export default function ReportExportActions({ onDownload, disabled = false, busy = false }) {
  return (
    <div className="report-export-actions">
      <button
        type="button"
        className="button button-dark"
        onClick={() => onDownload('pdf')}
        disabled={disabled || busy}
      >
        {busy ? 'Generating…' : 'Download PDF'}
      </button>
      <button
        type="button"
        className="button button-secondary"
        onClick={() => onDownload('json')}
        disabled={disabled || busy}
      >
        {busy ? 'Generating…' : 'Download JSON'}
      </button>
    </div>
  );
}
