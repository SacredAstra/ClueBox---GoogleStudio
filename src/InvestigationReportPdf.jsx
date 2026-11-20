import { Document, Page, StyleSheet, Text, View, pdf } from '@react-pdf/renderer';

const styles = StyleSheet.create({
  page: {
    padding: 36,
    fontSize: 10,
    fontFamily: 'Helvetica',
    color: '#162230',
    lineHeight: 1.45,
  },
  header: {
    marginBottom: 18,
    paddingBottom: 10,
    borderBottomWidth: 1.5,
    borderBottomColor: '#1e3a5f',
  },
  eyebrow: {
    fontSize: 8,
    letterSpacing: 1.4,
    color: '#0e7490',
    marginBottom: 4,
    textTransform: 'uppercase',
  },
  title: {
    fontSize: 18,
    fontFamily: 'Helvetica-Bold',
    color: '#0b1020',
    marginBottom: 4,
  },
  metaRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 14,
    fontSize: 9,
    color: '#475569',
    marginTop: 4,
  },
  section: {
    marginTop: 14,
  },
  sectionTitle: {
    fontSize: 12,
    fontFamily: 'Helvetica-Bold',
    color: '#0f2942',
    marginBottom: 6,
    paddingBottom: 3,
    borderBottomWidth: 0.75,
    borderBottomColor: '#cbd5e1',
  },
  paragraph: {
    marginBottom: 6,
    color: '#1e293b',
  },
  card: {
    marginBottom: 8,
    padding: 8,
    borderWidth: 0.75,
    borderColor: '#cbd5e1',
    borderRadius: 3,
    backgroundColor: '#f8fafc',
  },
  cardTitle: {
    fontSize: 10,
    fontFamily: 'Helvetica-Bold',
    color: '#0f172a',
    marginBottom: 3,
  },
  mono: {
    fontFamily: 'Courier',
    fontSize: 8,
    color: '#334155',
    marginTop: 2,
  },
  badge: {
    fontSize: 8,
    fontFamily: 'Helvetica-Bold',
    color: '#0e7490',
    marginTop: 2,
  },
  bullet: {
    marginBottom: 4,
    paddingLeft: 8,
  },
  muted: {
    color: '#64748b',
    fontSize: 9,
  },
  footer: {
    position: 'absolute',
    bottom: 20,
    left: 36,
    right: 36,
    fontSize: 8,
    color: '#64748b',
    flexDirection: 'row',
    justifyContent: 'space-between',
    borderTopWidth: 0.5,
    borderTopColor: '#cbd5e1',
    paddingTop: 6,
  },
});

function InvestigationReportDocument({ report, leadInvestigator }) {
  const evidenceInventory = Array.isArray(report?.evidenceInventory) ? report.evidenceInventory : [];
  const timeline = Array.isArray(report?.timeline) ? report.timeline : [];
  const verifiedFindings = Array.isArray(report?.classifications?.verifiedFindings)
    ? report.classifications.verifiedFindings
    : [];
  const unverifiedLeads = Array.isArray(report?.classifications?.unverifiedLeads)
    ? report.classifications.unverifiedLeads
    : [];
  const unsupportedClaims = Array.isArray(report?.classifications?.unsupportedClaims)
    ? report.classifications.unsupportedClaims
    : [];
  const limitations = Array.isArray(report?.limitations) ? report.limitations : [];
  const unresolvedQuestions = Array.isArray(report?.unresolvedInvestigativeQuestions)
    ? report.unresolvedInvestigativeQuestions
    : [];
  const humanValidations = Array.isArray(report?.humanValidationResults)
    ? report.humanValidationResults
    : [];

  return (
    <Document
      title={`ClueBox Odyssey Investigation Report — ${report?.case?.caseId || 'Case'}`}
      author={leadInvestigator || 'ClueBox Odyssey Investigator'}
    >
      <Page size="A4" style={styles.page}>
        <View style={styles.header}>
          <Text style={styles.eyebrow}>ClueBox Odyssey · Digital Forensics Investigation Report</Text>
          <Text style={styles.title}>Case {report?.case?.caseId || 'Unspecified'}</Text>
          <View style={styles.metaRow}>
            <Text>Generated: {report?.generatedAt ? new Date(report.generatedAt).toLocaleString() : 'Unknown'}</Text>
            {leadInvestigator ? <Text>Lead Investigator: {leadInvestigator}</Text> : null}
            <Text>Evidence Items: {evidenceInventory.length}</Text>
            <Text>Timeline Events: {timeline.length}</Text>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>1. Investigation Summary & Conclusions</Text>
          <Text style={styles.paragraph}>
            {report?.case?.investigationSummary || 'No investigator summary was supplied.'}
          </Text>
          <Text style={styles.cardTitle}>Investigator Conclusions</Text>
          <Text style={styles.paragraph}>
            {report?.case?.investigatorConclusions || 'No investigator conclusions were recorded.'}
          </Text>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>2. Evidence Inventory & Integrity Verification</Text>
          {evidenceInventory.length === 0 ? (
            <Text style={styles.muted}>No evidence records included.</Text>
          ) : (
            evidenceInventory.map((item) => (
              <View key={item.evidenceId} style={styles.card} wrap={false}>
                <Text style={styles.cardTitle}>{item.filename}</Text>
                <Text style={styles.muted}>
                  ID: {item.evidenceId} · Type: {item.type} · Size: {item.size ?? 'Unknown'} bytes
                </Text>
                <Text style={styles.mono}>SHA-256: {item.sha256 || 'Unavailable'}</Text>
                <Text style={styles.badge}>
                  Integrity: {item.integrityStatus} · Custody Chain: {item.custodyStatus} ({item.custodyHistory?.length || 0} events)
                </Text>
              </View>
            ))
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>3. Analyst Validations ({humanValidations.length})</Text>
          {humanValidations.length === 0 ? (
            <Text style={styles.muted}>No manual analyst validations have been recorded.</Text>
          ) : (
            humanValidations.map((validation, index) => (
              <View key={`${validation.evidenceId}-${validation.module}-${index}`} style={styles.card} wrap={false}>
                <Text style={styles.cardTitle}>
                  {validation.module || 'Analysis'} · Status: {validation.status || 'NEEDS REVIEW'}
                </Text>
                <Text style={styles.muted}>
                  Evidence: {validation.evidenceId} · Analyst: {validation.analyst || 'Not recorded'}
                </Text>
                {validation.notes ? <Text style={styles.paragraph}>{validation.notes}</Text> : null}
              </View>
            ))
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>4. Findings Classification</Text>
          <Text style={styles.cardTitle}>Verified Findings ({verifiedFindings.length})</Text>
          {verifiedFindings.length === 0 ? (
            <Text style={styles.muted}>None verified by an authorized investigator.</Text>
          ) : (
            verifiedFindings.map((item, idx) => (
              <Text key={`vf-${idx}`} style={styles.bullet}>
                • {item.statement || item.note || JSON.stringify(item)} (Validated by: {item.validatedBy || 'Authorized investigator'})
              </Text>
            ))
          )}

          <Text style={[styles.cardTitle, { marginTop: 6 }]}>Unverified Leads ({unverifiedLeads.length})</Text>
          {unverifiedLeads.length === 0 ? (
            <Text style={styles.muted}>No unverified leads recorded.</Text>
          ) : (
            unverifiedLeads.slice(0, 40).map((item, idx) => (
              <Text key={`ul-${idx}`} style={styles.bullet}>
                • {item.statement || item.indicator || item.note || JSON.stringify(item)}
              </Text>
            ))
          )}

          {unsupportedClaims.length > 0 ? (
            <>
              <Text style={[styles.cardTitle, { marginTop: 6 }]}>Unsupported AI Claims ({unsupportedClaims.length})</Text>
              {unsupportedClaims.map((item, idx) => (
                <Text key={`uc-${idx}`} style={styles.bullet}>
                  • {item.statement || JSON.stringify(item)}
                </Text>
              ))}
            </>
          ) : null}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>5. Investigation Timeline ({timeline.length})</Text>
          {timeline.length === 0 ? (
            <Text style={styles.muted}>No timeline events generated.</Text>
          ) : (
            timeline.slice(0, 80).map((event, idx) => (
              <View key={event.id || `tl-${idx}`} style={styles.card} wrap={false}>
                <Text style={styles.cardTitle}>
                  {event.timestamp || 'Timestamp uncertain'} · {event.sourceModule} · {event.filename}
                </Text>
                <Text style={styles.paragraph}>{event.description}</Text>
                <Text style={styles.muted}>
                  Status: {event.timestampStatus} · Validation: {event.validationStatus} · {event.classification}
                </Text>
              </View>
            ))
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>6. Limitations & Unresolved Questions</Text>
          {limitations.map((limitation, idx) => (
            <Text key={`lim-${idx}`} style={styles.bullet}>• {limitation}</Text>
          ))}
          {unresolvedQuestions.length > 0 ? (
            <>
              <Text style={[styles.cardTitle, { marginTop: 6 }]}>Unresolved Investigative Questions</Text>
              {unresolvedQuestions.map((question, idx) => (
                <Text key={`uq-${idx}`} style={styles.bullet}>• {question}</Text>
              ))}
            </>
          ) : null}
        </View>

        <View style={styles.footer} fixed>
          <Text>ClueBox Odyssey — Private Local Forensic Workspace</Text>
          <Text render={({ pageNumber, totalPages }) => `Page ${pageNumber} of ${totalPages}`} />
        </View>
      </Page>
    </Document>
  );
}

export async function generateInvestigationPdf(report, leadInvestigator = '') {
  return pdf(
    <InvestigationReportDocument report={report} leadInvestigator={leadInvestigator} />,
  ).toBlob();
}
