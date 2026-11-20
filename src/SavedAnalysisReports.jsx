function formatReviewedAt(value) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function summarizeReport(moduleKey, analysis) {
  if (moduleKey === 'exifValidation') {
    return 'EXIF metadata validation';
  }
  if (moduleKey === 'registryAnalysis') {
    const count = analysis.report?.artifacts?.length ?? 0;
    return `${analysis.report?.hiveType || 'Unknown'} hive · ${analysis.report?.keyCount ?? 0} keys · ${count} artifacts`;
  }
  if (moduleKey === 'pcapAnalysis') {
    const packets = analysis.report?.packetCount ?? analysis.report?.packets?.length ?? 0;
    const connections = analysis.report?.connections?.length ?? 0;
    const leads = analysis.report?.leads?.length ?? 0;
    return `${analysis.report?.format || 'PCAP'} · ${packets} packets · ${connections} connections · ${leads} leads`;
  }
  if (moduleKey === 'sqliteAnalysis') {
    const tables = analysis.report?.tableCount ?? 0;
    const views = analysis.report?.viewCount ?? 0;
    const rows = analysis.report?.recordCount ?? 0;
    return `SQLite · ${tables} tables · ${views} views · ${rows} rows`;
  }
  return 'Forensic analysis';
}

export default function SavedAnalysisReports({ records = [], caseId = '' }) {
  const savedItems = [];

  for (const record of records) {
    if (record.exifValidation) {
      savedItems.push({
        id: `${record.id}-exif`,
        moduleLabel: 'EXIF Metadata',
        evidenceName: record.name,
        evidenceSha256: record.sha256,
        status: record.exifValidation.status,
        analyst: record.exifValidation.analyst,
        reviewedAt: record.exifValidation.reviewedAt,
        notes: record.exifValidation.notes,
        references: record.exifValidation.artifactReferences || [],
        summary: summarizeReport('exifValidation', record.exifValidation),
      });
    }
    for (const [key, label] of [
      ['registryAnalysis', 'Windows Registry'],
      ['pcapAnalysis', 'PCAP Network'],
      ['sqliteAnalysis', 'SQLite Database'],
    ]) {
      const saved = record[key];
      if (!saved) continue;
      savedItems.push({
        id: `${record.id}-${key}`,
        moduleLabel: label,
        evidenceName: record.name,
        evidenceSha256: saved.sourceSha256 || record.sha256,
        status: saved.status,
        analyst: saved.analyst,
        reviewedAt: saved.reviewedAt,
        notes: saved.notes,
        references: saved.artifactReferences || [],
        summary: summarizeReport(key, saved),
      });
    }
    if (Array.isArray(record.copilotFindings)) {
      for (const finding of record.copilotFindings) {
        const latestValidation = Array.isArray(finding.validationHistory)
          ? finding.validationHistory.at(-1)
          : null;
        savedItems.push({
          id: `${record.id}-copilot-${finding.id}`,
          moduleLabel: 'AI Copilot Finding',
          evidenceName: record.name,
          evidenceSha256: record.sha256,
          status: finding.validationStatus || 'NEEDS REVIEW',
          analyst: latestValidation?.analyst || 'Awaiting human review',
          reviewedAt: latestValidation?.reviewedAt || finding.createdAt,
          notes: latestValidation?.notes || finding.question || '',
          references: (finding.observedEvidence || []).map((fact) => `${fact.referenceId}: ${fact.reference}`).slice(0, 8),
          summary: `${finding.interpretations?.length || 0} interpretations · ${finding.investigativeLeads?.length || 0} leads · ${finding.recommendations?.length || 0} recommendations`,
        });
      }
    }
  }

  return (
    <section className="saved-analysis-reports" aria-label="Saved analysis reports">
      <div className="saved-analysis-heading">
        <div>
          <p className="eyebrow">SAVED VALIDATIONS</p>
          <h3>Saved Analysis Reports</h3>
          <p>
            {caseId
              ? `Analyst-saved EXIF, Registry, PCAP, SQLite, and Copilot records filed under ${caseId}.`
              : 'Open a case to inspect saved forensic analysis reports.'}
          </p>
        </div>
        <span className="saved-analysis-count" aria-label={`${savedItems.length} saved analysis reports`}>
          {savedItems.length}
        </span>
      </div>

      {savedItems.length === 0 ? (
        <p className="saved-analysis-empty">
          No analysis reports have been saved for this case yet. Run an analysis module and save analyst validation to see it listed here.
        </p>
      ) : (
        <div className="saved-analysis-list">
          {savedItems.map((item) => (
            <details key={item.id} className="saved-analysis-item">
              <summary>
                <span>{item.moduleLabel}</span>
                <span>{item.evidenceName}</span>
                <span>{item.status}</span>
              </summary>
              <dl>
                <div>
                  <dt>Summary</dt>
                  <dd>{item.summary}</dd>
                </div>
                <div>
                  <dt>Analyst</dt>
                  <dd>
                    {item.analyst}
                    <span>Reviewed: {formatReviewedAt(item.reviewedAt)}</span>
                  </dd>
                </div>
                <div>
                  <dt>Source SHA-256</dt>
                  <dd>
                    <code>{item.evidenceSha256 || 'Unavailable'}</code>
                  </dd>
                </div>
                {item.notes && (
                  <div>
                    <dt>Notes</dt>
                    <dd>{item.notes}</dd>
                  </div>
                )}
                {item.references.length > 0 && (
                  <div>
                    <dt>Artifact references</dt>
                    <dd>
                      <ul>
                        {item.references.map((ref, idx) => (
                          <li key={`${item.id}-ref-${idx}`}>{ref}</li>
                        ))}
                      </ul>
                    </dd>
                  </div>
                )}
              </dl>
            </details>
          ))}
        </div>
      )}
    </section>
  );
}
