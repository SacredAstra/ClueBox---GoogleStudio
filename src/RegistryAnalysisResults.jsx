import { useMemo, useState } from 'react';

const PREVIEW_LIMIT = 180;

function formatValueContent(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value, null, 2);
}

function isBinaryValue(entry) {
  const type = String(entry?.type || '').toUpperCase();
  return type.includes('BINARY') || type === 'REG_NONE' || Boolean(entry?.data?.hexPreview);
}

export default function RegistryAnalysisResults({ report, evidence }) {
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [expandedValues, setExpandedValues] = useState({});
  const [copyStatus, setCopyStatus] = useState('');

  const artifacts = useMemo(
    () => (Array.isArray(report?.artifacts) ? report.artifacts : []),
    [report],
  );
  const warnings = useMemo(
    () => (Array.isArray(report?.warnings) ? report.warnings : []),
    [report],
  );

  const categories = useMemo(
    () => [...new Set(artifacts.map((artifact) => artifact.type || 'Registry artifact'))].sort(),
    [artifacts],
  );

  const filteredArtifacts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return artifacts.filter((artifact) => {
      const category = artifact.type || 'Registry artifact';
      if (selectedCategory !== 'ALL' && category !== selectedCategory) return false;
      if (!q) return true;
      if (category.toLowerCase().includes(q)) return true;
      if (String(artifact.keyPath || '').toLowerCase().includes(q)) return true;
      return (artifact.values || []).some((entry) => (
        String(entry.name || '').toLowerCase().includes(q)
        || formatValueContent(entry.data).toLowerCase().includes(q)
      ));
    });
  }, [artifacts, search, selectedCategory]);

  const groupedArtifacts = useMemo(() => {
    const groups = new Map();
    for (const artifact of filteredArtifacts) {
      const category = artifact.type || 'Registry artifact';
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(artifact);
    }
    return [...groups.entries()];
  }, [filteredArtifacts]);

  const copyText = async (text, label) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setCopyStatus(`Copied ${label} to clipboard.`);
      } else {
        setCopyStatus(`Clipboard unavailable in this browser.`);
      }
    } catch {
      setCopyStatus(`Could not copy ${label}.`);
    }
  };

  const toggleExpand = (key) => {
    setExpandedValues((current) => ({ ...current, [key]: !current[key] }));
  };

  return (
    <div className="registry-results">
      <div className="registry-results-summary">
        <div>
          <span>Hive type</span>
          <strong>{report?.hiveType || 'Unknown'}</strong>
        </div>
        <div>
          <span>Keys parsed</span>
          <strong>{report?.keyCount ?? 0}</strong>
        </div>
        <div>
          <span>Artifacts</span>
          <strong>{artifacts.length}</strong>
        </div>
        {evidence?.sha256 && (
          <div>
            <span>Source SHA-256</span>
            <code>{evidence.sha256.slice(0, 16)}…</code>
          </div>
        )}
      </div>

      <div className="registry-result-filters">
        <label>
          Filter artifacts
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search key paths, value names, or data"
          />
        </label>
        <label>
          Category
          <select
            value={selectedCategory}
            onChange={(event) => setSelectedCategory(event.target.value)}
          >
            <option value="ALL">All categories ({artifacts.length})</option>
            {categories.map((category) => (
              <option key={category} value={category}>
                {category}
              </option>
            ))}
          </select>
        </label>
      </div>

      {copyStatus && (
        <p className="registry-copy-status" role="status">
          {copyStatus}
        </p>
      )}

      {groupedArtifacts.length === 0 ? (
        <p className="registry-analysis-copy">
          {artifacts.length === 0
            ? 'No forensic registry artifacts matched the built-in artifact rules for this hive.'
            : 'No artifacts match the current filter.'}
        </p>
      ) : (
        groupedArtifacts.map(([category, items]) => (
          <details key={category} className="registry-artifact-category" open>
            <summary>
              {category}
              <span>{items.length}</span>
            </summary>
            <ul className="registry-artifact-list">
              {items.map((artifact, artifactIndex) => {
                const artifactKey = `${category}-${artifact.keyPath}-${artifactIndex}`;
                const values = Array.isArray(artifact.values) ? artifact.values : [];
                return (
                  <li key={artifactKey} className="registry-artifact">
                    <div className="registry-artifact-heading">
                      <strong>{artifact.type}</strong>
                      <button
                        type="button"
                        className="registry-inline-action"
                        onClick={() => copyText(artifact.keyPath || '', 'key path')}
                      >
                        Copy path
                      </button>
                    </div>
                    <code className="registry-artifact-path">{artifact.keyPath}</code>
                    {artifact.lastWrittenAt && (
                      <span className="registry-binary-note">
                        Last written: {artifact.lastWrittenAt}
                      </span>
                    )}
                    {values.length > 0 && (
                      <ul className="registry-values">
                        {values.map((entry, valueIndex) => {
                          const valKey = `${artifactKey}-${entry.name}-${valueIndex}`;
                          const formatted = formatValueContent(entry.data);
                          const longValue = formatted.length > PREVIEW_LIMIT;
                          const isExpanded = Boolean(expandedValues[valKey]);
                          const displayText = longValue && !isExpanded
                            ? `${formatted.slice(0, PREVIEW_LIMIT)}…`
                            : formatted;
                          return (
                            <li key={valKey} className="registry-value">
                              <div className="registry-value-heading">
                                <strong>{entry.name || '(Default)'}</strong>
                                <button
                                  type="button"
                                  className="registry-inline-action"
                                  onClick={() => copyText(formatted, entry.name || 'value')}
                                >
                                  Copy
                                </button>
                              </div>
                              <code className={`registry-value-content${isExpanded ? ' is-expanded' : ''}`}>
                                {displayText || '(empty)'}
                              </code>
                              {isBinaryValue(entry) && (
                                <span className="registry-binary-note">
                                  Type: {entry.type || 'REG_BINARY'} (binary preview)
                                </span>
                              )}
                              {longValue && (
                                <button
                                  type="button"
                                  className="registry-inline-action registry-expand-value"
                                  onClick={() => toggleExpand(valKey)}
                                >
                                  {isExpanded ? 'Collapse value' : 'Expand full value'}
                                </button>
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </li>
                );
              })}
            </ul>
          </details>
        ))
      )}

      {warnings.length > 0 && (
        <details className="registry-warning-details">
          <summary>
            Parser warnings
            <span>{warnings.length}</span>
          </summary>
          <ul>
            {warnings.map((warning, idx) => (
              <li key={`warn-${idx}`} className="registry-warning">
                {warning}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
