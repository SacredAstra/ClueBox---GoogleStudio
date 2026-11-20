import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import {
  addCustodyEvent,
  archiveEvidenceRecord,
  downloadEvidence,
  getCaseDetails,
  getCaseRecords,
  getCases,
  openVault,
  saveCopilotFinding,
  saveCaseDetails,
  saveExifValidation,
  savePcapAnalysis,
  saveRegistryAnalysis,
  saveSqliteAnalysis,
  saveEvidence,
  replaceEvidence,
  validateCopilotFinding,
  verifyCustody,
} from './vault';
import EvidenceIntegrity from './EvidenceIntegrity';
import { extractExifMetadata } from './exif';
import { parsePcap } from './pcap';
import { parseRegistryHive } from './registry';
import RegistryAnalysisResults from './RegistryAnalysisResults';
import SavedAnalysisReports from './SavedAnalysisReports';
import ReportExportActions from './ReportExportActions';
import { analyzeSqlite } from './sqlite';
import {
  buildCopilotEvidenceContext,
  callCopilot,
  combineCopilotResponses,
  COPILOT_UNAVAILABLE_MESSAGE,
  getCopilotRequestSize,
  makeCopilotFinding,
  makeCopilotQuestion,
  MAX_COPILOT_REQUEST_BYTES,
  partitionCopilotFacts,
  validateCopilotResponse,
} from './copilot';
import {
  createInvestigationReport,
  createTimelineEvents,
  filterTimelineEvents,
  timelineToCsv,
} from './timeline';
import { getCaseMembershipRole, registerLocalCase } from './supabase/cases';
import { supabase, supabaseConfigured } from './supabase/client';
import { readNavigationState, writeNavigationState } from './navigation-state';
import ClueBoxLogo from './ClueBoxLogo';
import './App.css';

const formatBytes = (bytes) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const formatDate = (value) => new Date(value).toLocaleString(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
});

const formatTimestampSource = (value) => value === null || value === undefined
  ? 'Not provided'
  : typeof value === 'object'
    ? JSON.stringify(value)
    : String(value);

const exifLabels = {
  cameraMake: 'Camera make',
  cameraModel: 'Camera model',
  capturedAt: 'Date captured',
  digitizedAt: 'Date digitized',
  modifiedAt: 'Date modified',
  software: 'Software',
  lensModel: 'Lens model',
  imageWidth: 'Image width',
  imageHeight: 'Image height',
  orientation: 'Orientation',
  gpsLatitude: 'GPS latitude',
  gpsLongitude: 'GPS longitude',
  gpsAltitudeMeters: 'GPS altitude',
};

function Icon({ name, size = 18 }) {
  const paths = {
    lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /><path d="M12 14v3" /></>,
    plus: <><path d="M12 5v14M5 12h14" /></>,
    upload: <><path d="M12 16V4m0 0L7 9m5-5 5 5" /><path d="M5 15v4a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-4" /></>,
    file: <><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z" /><path d="M13 3v7h7" /></>,
    download: <><path d="M12 4v12m0 0 5-5m-5 5-5-5" /><path d="M5 20h14" /></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z" /><path d="m9 12 2 2 4-4" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 4 4" /></>,
    eye: <><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></>,
    eyeOff: <><path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8" /><path d="M9.9 5.2A10.7 10.7 0 0 1 12 5c6.4 0 10 7 10 7a15.7 15.7 0 0 1-3.1 3.8M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7c1.1 0 2.1-.2 3-.5" /></>,
    arrow: <><path d="M5 12h14m-6-6 6 6-6 6" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    close: <><path d="m18 6-12 12M6 6l12 12" /></>,
    folder: <><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><path d="M3 10h18" /></>,
    folderSearch: <><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v4" /><path d="M3 10h12" /><circle cx="16" cy="16" r="3" /><path d="m18.2 18.2 2 2" /></>,
    camera: <><path d="M4 7h3l1.5-2h7L17 7h3a1 1 0 0 1 1 1v11H3V8a1 1 0 0 1 1-1z" /><circle cx="12" cy="13" r="3.5" /></>,
    database: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7" /></>,
    network: <><circle cx="5" cy="12" r="2" /><circle cx="19" cy="6" r="2" /><circle cx="19" cy="18" r="2" /><path d="m7 11 10-4M7 13l10 4M19 8v8" /></>,
    activity: <><path d="M3 12h4l3-8 4 16 3-8h4" /></>,
    fileText: <><path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10z" /><path d="M13 3v7h7M8 14h8M8 18h6" /></>,
    sparkles: <><path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z" /><path d="m19 14 .9 2.1L22 17l-2.1.9L19 20l-.9-2.1L16 17l2.1-.9z" /></>,
    chevron: <path d="m9 18 6-6-6-6" />,
  };

  return (
    <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      {paths[name]}
    </svg>
  );
}

function App() {
  const [initialNavigation] = useState(readNavigationState);
  const [welcomeVisible, setWelcomeVisible] = useState(() => supabaseConfigured || !initialNavigation.entered);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeWorkspace, setActiveWorkspace] = useState(initialNavigation.workspace);
  const [copilotPanelOpen, setCopilotPanelOpen] = useState(false);
  const [copilotPanelMinimized, setCopilotPanelMinimized] = useState(false);
  const [copilotPanelExpanded, setCopilotPanelExpanded] = useState(false);
  const [db, setDb] = useState(null);
  const [caseId, setCaseId] = useState(initialNavigation.caseId);
  const [caseInput, setCaseInput] = useState(initialNavigation.caseId);
  const [caseDetails, setCaseDetails] = useState(null);
  const [caseDetailsBusy, setCaseDetailsBusy] = useState(false);
  const [cases, setCases] = useState([]);
  const [records, setRecords] = useState([]);
  const [selectedId, setSelectedId] = useState(initialNavigation.selectedId);
  const [evidenceListView, setEvidenceListView] = useState('active');
  const [evidenceAction, setEvidenceAction] = useState(null);
  const [evidenceActionAnalyst, setEvidenceActionAnalyst] = useState('');
  const [evidenceActionReason, setEvidenceActionReason] = useState('');
  const [replacementFile, setReplacementFile] = useState(null);
  const [custodian, setCustodian] = useState('');
  const [custodyAction, setCustodyAction] = useState('Evidence reviewed');
  const [exifValidationStatus, setExifValidationStatus] = useState('NEEDS REVIEW');
  const [exifAnalyst, setExifAnalyst] = useState('');
  const [exifNotes, setExifNotes] = useState('');
  const [exifArtifactReferences, setExifArtifactReferences] = useState('');
  const [registryReport, setRegistryReport] = useState(null);
  const [registryValidationStatus, setRegistryValidationStatus] = useState('NEEDS REVIEW');
  const [registryAnalyst, setRegistryAnalyst] = useState('');
  const [registryNotes, setRegistryNotes] = useState('');
  const [registryArtifactReferences, setRegistryArtifactReferences] = useState('');
  const [pcapReport, setPcapReport] = useState(null);
  const [pcapValidationStatus, setPcapValidationStatus] = useState('NEEDS REVIEW');
  const [pcapAnalyst, setPcapAnalyst] = useState('');
  const [pcapNotes, setPcapNotes] = useState('');
  const [pcapArtifactReferences, setPcapArtifactReferences] = useState('');
  const [sqliteReport, setSqliteReport] = useState(null);
  const [sqliteValidationStatus, setSqliteValidationStatus] = useState('NEEDS REVIEW');
  const [sqliteAnalyst, setSqliteAnalyst] = useState('');
  const [sqliteNotes, setSqliteNotes] = useState('');
  const [sqliteArtifactReferences, setSqliteArtifactReferences] = useState('');
  const [query, setQuery] = useState('');
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [navigationWarning, setNavigationWarning] = useState('');
  const [custodyChainValid, setCustodyChainValid] = useState(true);
  const [authSession, setAuthSession] = useState(null);
  const [authReady, setAuthReady] = useState(!supabase);
  const [authPanelOpen, setAuthPanelOpen] = useState(false);
  const [authMode, setAuthMode] = useState('signIn');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authPasswordVisible, setAuthPasswordVisible] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [authMessage, setAuthMessage] = useState('');
  const [authError, setAuthError] = useState('');
  const [teamCaseRegistration, setTeamCaseRegistration] = useState(null);
  const [copilotAvailability, setCopilotAvailability] = useState(COPILOT_UNAVAILABLE_MESSAGE);
  const [copilotConfigured, setCopilotConfigured] = useState(false);
  const [copilotSelectedIds, setCopilotSelectedIds] = useState([]);
  const [copilotQuestion, setCopilotQuestion] = useState('');
  const [copilotLatestQuestion, setCopilotLatestQuestion] = useState('');
  const [copilotFacts, setCopilotFacts] = useState([]);
  const [copilotApprovedFactIds, setCopilotApprovedFactIds] = useState([]);
  const [copilotApproved, setCopilotApproved] = useState(false);
  const [copilotResponse, setCopilotResponse] = useState(null);
  const [copilotConversation, setCopilotConversation] = useState([]);
  const [copilotBusy, setCopilotBusy] = useState(false);
  const [copilotError, setCopilotError] = useState('');
  const [copilotReviews, setCopilotReviews] = useState({});
  const [copilotToolkitScanLog, setCopilotToolkitScanLog] = useState([]);
  const [copilotToolkitScanResults, setCopilotToolkitScanResults] = useState(null);
  const [copilotLiveAnalyses, setCopilotLiveAnalyses] = useState({});
  const [autoDocumentCopilot, setAutoDocumentCopilot] = useState(true);
  const [copilotMiniTab, setCopilotMiniTab] = useState('chat');
  const [copilotWorkspaceTab, setCopilotWorkspaceTab] = useState('chat');
  const [timelineCaseId, setTimelineCaseId] = useState('');
  const [timelineRecords, setTimelineRecords] = useState([]);
  const [timelineIntegrity, setTimelineIntegrity] = useState({});
  const [timelineViewMode, setTimelineViewMode] = useState('standard');
  const [aiTimelineAnalysis, setAiTimelineAnalysis] = useState(null);
  const [aiTimelineBusy, setAiTimelineBusy] = useState(false);
  const [aiTimelineError, setAiTimelineError] = useState('');
  const [aiTimelineSavedFinding, setAiTimelineSavedFinding] = useState(null);
  const [aiTimelineReview, setAiTimelineReview] = useState({
    status: 'VERIFIED',
    analyst: '',
    independentMethod: '',
    notes: '',
    attested: false,
  });
  const [timelineFilters, setTimelineFilters] = useState({
    evidenceId: '',
    module: '',
    startDate: '',
    endDate: '',
    validationStatus: '',
    timestampStatus: '',
  });
  const [timelineError, setTimelineError] = useState('');
  const [reportSummary, setReportSummary] = useState('');
  const [reportConclusions, setReportConclusions] = useState('');
  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState('');
  const [reportNotice, setReportNotice] = useState('');
  const [caseDropdownOpen, setCaseDropdownOpen] = useState(false);
  const [casePopupOpen, setCasePopupOpen] = useState(false);
  const fileInput = useRef(null);
  const caseInputRef = useRef(null);
  const caseDropdownRef = useRef(null);
  const workspaceRef = useRef(null);
  const landingAuthRef = useRef(null);
  const appRootRef = useRef(null);
  const copilotLauncherRef = useRef(null);
  const copilotQuestionRef = useRef(null);
  const copilotConversationRef = useRef(null);

  const navigateToWorkspace = (workspace) => {
    if (['exif', 'registry', 'pcap', 'sqlite'].includes(workspace)
      && records.find((record) => record.id === selectedId)?.archivedAt) {
      setSelectedId(activeRecords[0]?.id ?? null);
    }
    setActiveWorkspace(workspace);
    if (workspaceRef.current) workspaceRef.current.scrollTop = 0;
  };
  const openLandingAuth = (mode) => {
    setAuthMode(mode);
    setAuthPasswordVisible(false);
    setAuthError('');
    setAuthMessage('');
    setAuthPanelOpen(true);
    requestAnimationFrame(() => {
      if (typeof landingAuthRef.current?.scrollIntoView === 'function') {
        landingAuthRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  };
  const openModuleCard = (module) => {
    if (module === 'copilot') {
      setCopilotPanelMinimized(false);
      setCopilotPanelOpen(true);
      return;
    }
    if (module === 'cases') {
      navigateToWorkspace('cases');
      return;
    }
    navigateToWorkspace(module);
  };
  const closeCopilotPanel = () => {
    setCopilotPanelOpen(false);
    setCopilotPanelMinimized(false);
    copilotLauncherRef.current?.focus();
  };

  useEffect(() => {
    if (!copilotPanelOpen) return undefined;
    if (!copilotPanelMinimized) copilotQuestionRef.current?.focus();
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') closeCopilotPanel();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [copilotPanelOpen, copilotPanelMinimized]);

  useEffect(() => {
    const conversation = copilotConversationRef.current;
    if (conversation) conversation.scrollTop = conversation.scrollHeight;
  }, [copilotConversation, copilotBusy]);

  useEffect(() => {
    if (!supabase) return undefined;
    let active = true;
    let authEventObserved = false;
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      authEventObserved = true;
      setAuthSession(session);
      setAuthReady(true);
      if (event === 'SIGNED_OUT') {
        setWelcomeVisible(true);
        setAuthPanelOpen(false);
      } else if (event === 'SIGNED_IN') {
        setWelcomeVisible(false);
        setAuthPanelOpen(false);
      } else if (event === 'INITIAL_SESSION' && session && initialNavigation.entered) {
        setWelcomeVisible(false);
      }
    });
    supabase.auth.getSession()
      .then(({ data, error: sessionError }) => {
        if (!active || authEventObserved) return;
        if (sessionError) setAuthError(sessionError.message);
        setAuthSession(data.session);
        if (data.session && initialNavigation.entered) setWelcomeVisible(false);
        setAuthReady(true);
      })
      .catch((sessionError) => {
        if (!active || authEventObserved) return;
        setAuthError(sessionError.message || 'Could not restore the sign-in session.');
        setAuthReady(true);
      });
    return () => {
      active = false;
      subscription.unsubscribe();
    };
  }, [initialNavigation]);

  useEffect(() => {
    if (!authReady) return;
    const saved = writeNavigationState({
      entered: !welcomeVisible,
      workspace: activeWorkspace,
      caseId,
      selectedId,
    });
    setNavigationWarning(saved
      ? ''
      : 'This browser could not save the active workspace for refresh recovery. Your evidence and case data remain unchanged.');
  }, [authReady, welcomeVisible, activeWorkspace, caseId, selectedId]);

  useEffect(() => {
    if (caseId) setTimelineCaseId(caseId);
  }, [caseId]);

  useEffect(() => {
    let active = true;
    if (!db || !timelineCaseId) {
      setTimelineRecords([]);
      setTimelineIntegrity({});
      return () => { active = false; };
    }
    getCaseRecords(db, timelineCaseId)
      .then(async (items) => {
        const checks = await Promise.all(items.map(async (record) => {
          let custody = false;
          try {
            custody = await verifyCustody(record.custody);
          } catch {
            custody = false;
          }
          return [record.id, { custody }];
        }));
        if (active) {
          setTimelineRecords(items);
          setTimelineIntegrity(Object.fromEntries(checks));
          setTimelineError('');
          const savedTimelineEntries = items
            .flatMap((record) => (record.copilotFindings || [])
              .filter((finding) => finding.analysisType === 'timeline')
              .map((finding) => ({ evidenceId: record.id, finding })))
            .sort((a, b) => String(b.finding.createdAt || '').localeCompare(String(a.finding.createdAt || '')));
          const latestSaved = savedTimelineEntries[0];
          if (latestSaved) {
            const { evidenceId, finding } = latestSaved;
            setAiTimelineAnalysis((current) => (current?.caseId === timelineCaseId && current?.findingId === finding.id
              ? current
              : {
                caseId: timelineCaseId,
                findingId: finding.id,
                generatedAt: finding.createdAt,
                response: finding,
                facts: finding.observedEvidence || [],
                sourceEventCount: finding.analyzedTimeline?.length || 0,
              }));
            setAiTimelineSavedFinding({
              evidenceId,
              findingId: finding.id,
              status: finding.validationStatus || 'NEEDS REVIEW',
              validationHistory: finding.validationHistory || [],
            });
          } else {
            setAiTimelineAnalysis((current) => (current?.caseId === timelineCaseId ? current : null));
            setAiTimelineSavedFinding((current) => (current && items.some((r) => r.id === current.evidenceId) ? current : null));
          }
        }
      })
      .catch((timelineLoadError) => {
        if (active) setTimelineError(timelineLoadError.message || 'Could not load timeline case evidence.');
      });
    return () => { active = false; };
  }, [db, timelineCaseId, records]);

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      try {
        if (!window.crypto?.subtle) {
          throw new Error('Secure browser cryptography is unavailable. Open this app over HTTPS or localhost.');
        }
        if (!window.indexedDB) throw new Error('This browser does not support private local evidence storage.');
        const vault = await openVault();
        const storedCases = await getCases(vault);
        if (active) {
          setDb(vault);
          setCases(storedCases);
        }
      } catch (vaultError) {
        if (active) setError(vaultError.message || 'The private vault could not be opened.');
      }
    };
    initialize();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    if (!db || !caseId) {
      setRecords([]);
      setSelectedId(null);
      setCopilotSelectedIds([]);
      setCopilotFacts([]);
      setCopilotApprovedFactIds([]);
      setCopilotResponse(null);
      setCopilotConversation([]);
      setCopilotLatestQuestion('');
      return () => { active = false; };
    }
    getCaseRecords(db, caseId)
      .then((items) => {
        if (active) {
          setRecords(items);
          const preferredId = initialNavigation.caseId === caseId
            ? initialNavigation.selectedId
            : selectedId;
          const preferredRecord = items.find((item) => item.id === preferredId);
          if (preferredRecord?.archivedAt && activeWorkspace === 'evidence') setEvidenceListView('archived');
          else setEvidenceListView('active');
          setSelectedId(preferredRecord && (!preferredRecord.archivedAt || activeWorkspace === 'evidence')
            ? preferredId
            : items.find((item) => !item.archivedAt)?.id ?? null);
          setCopilotSelectedIds([]);
          setCopilotFacts([]);
          setCopilotApprovedFactIds([]);
          setCopilotResponse(null);
          setCopilotConversation([]);
          setCopilotLatestQuestion('');
        }
      })
      .catch((vaultError) => {
        if (active) setError(vaultError.message || 'Could not read this case from the vault.');
      });
    return () => { active = false; };
  }, [db, caseId]);

  useEffect(() => {
    let active = true;
    if (!db || !caseId) {
      setCaseDetails(null);
      return () => { active = false; };
    }
    getCaseDetails(db, caseId)
      .then((details) => {
        if (active) setCaseDetails(details);
      })
      .catch((vaultError) => {
        if (active) setError(vaultError.message || 'Could not load this case details.');
      });
    return () => { active = false; };
  }, [db, caseId]);

  useEffect(() => {
    let active = true;
    callCopilot({
      supabaseUrl: supabaseConfigured && authSession?.access_token ? import.meta.env.VITE_SUPABASE_URL : '',
      publishableKey: supabaseConfigured && authSession?.access_token ? import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY : '',
      accessToken: authSession?.access_token || '',
      action: 'status',
    })
      .then((status) => {
        if (active) {
          setCopilotConfigured(status.available === true);
          setCopilotAvailability(status.available
            ? (status.message || 'AI Forensic Copilot ready — full toolkit observatory active.')
            : (status.message || COPILOT_UNAVAILABLE_MESSAGE));
        }
      })
      .catch((availabilityError) => {
        if (active) {
          setCopilotConfigured(false);
          setCopilotAvailability(availabilityError.message || 'AI Copilot unavailable — secure backend not reachable.');
        }
      });
    return () => { active = false; };
  }, [authSession]);

  const selectedRecord = records.find((record) => record.id === selectedId);
  const activeCaseRegistration = teamCaseRegistration?.caseId === caseId
    && teamCaseRegistration?.userId === authSession?.user?.id
    ? teamCaseRegistration
    : null;
  const teamCaseRegistered = activeCaseRegistration?.status === 'registered';
  const copilotUsesTeamBackend = Boolean(supabaseConfigured && authSession?.access_token);
  const copilotAccessReady = copilotConfigured && (!copilotUsesTeamBackend || teamCaseRegistered);
  const canManageCaseEvidence = !supabaseConfigured || (
    teamCaseRegistered
    && ['admin', 'investigator'].includes(activeCaseRegistration?.role)
  );
  const activeRecords = records.filter((record) => !record.archivedAt);
  const archivedRecords = records.filter((record) => Boolean(record.archivedAt));
  const activeEvidenceSelection = activeRecords.some((record) => record.id === selectedId)
    ? selectedId
    : '';
  const copilotSelectedFacts = copilotFacts.filter((fact) => copilotApprovedFactIds.includes(fact.referenceId));
  const copilotRequestBatches = useMemo(
    () => copilotQuestion.trim() && copilotSelectedFacts.length
      ? partitionCopilotFacts(copilotQuestion, copilotSelectedFacts, caseId)
      : [],
    [copilotQuestion, copilotFacts, copilotApprovedFactIds, caseId],
  );
  const savedCopilotFindings = records.flatMap((record) => (
    (record.copilotFindings || []).map((finding) => ({ ...finding, evidenceRecord: record }))
  ));
  const timelineEvents = useMemo(
    () => timelineCaseId ? createTimelineEvents(timelineCaseId, timelineRecords, timelineIntegrity) : [],
    [timelineCaseId, timelineRecords, timelineIntegrity],
  );
  const filteredTimelineEvents = useMemo(
    () => filterTimelineEvents(timelineEvents, timelineFilters),
    [timelineEvents, timelineFilters],
  );
  const timelineModules = useMemo(
    () => [...new Set(timelineEvents.map((event) => event.sourceModule))].sort(),
    [timelineEvents],
  );
  const visibleEvidenceRecords = evidenceListView === 'archived' ? archivedRecords : activeRecords;
  const filteredRecords = visibleEvidenceRecords.filter((record) => (
    record.name.toLowerCase().includes(query.toLowerCase())
    || record.sha256.toLowerCase().includes(query.toLowerCase())
  ));
  const savedAnalysisCount = activeRecords.reduce((count, record) => count
    + Number(Boolean(record.exifValidation))
    + Number(Boolean(record.registryAnalysis))
    + Number(Boolean(record.pcapAnalysis))
    + Number(Boolean(record.sqliteAnalysis)), 0);
  const workspaces = {
    overview: ['Command center', 'Case activity, evidence totals, and service status.'],
    cases: ['Case Management', 'Review and update case details without changing its evidence.'],
    evidence: ['Evidence Locker', 'Browse, add, and inspect evidence with its integrity and custody history.'],
    exif: ['EXIF Analysis', 'Review image metadata and record manual analyst validation.'],
    registry: ['Windows Registry', 'Analyze offline registry hives and review extracted artifacts.'],
    pcap: ['PCAP Analysis', 'Inspect packet, endpoint, and connection evidence.'],
    sqlite: ['SQLite Analysis', 'Review database schemas, records, and timestamp candidates.'],
    timeline: ['Investigation Timeline', 'Correlate source events while preserving timestamp certainty.'],
    reports: ['Investigation Reports', 'Prepare and export a case report without modifying evidence.'],
    copilot: ['AI Forensic Copilot', 'Full-toolkit observatory, evidence fact & explanation scanner, workflow planner, and custodian verification.'],
  };
  const analysisWorkspace = ['exif', 'registry', 'pcap', 'sqlite'].includes(activeWorkspace);
  const evidenceWorkspaceVisible = ['evidence', ...['exif', 'registry', 'pcap', 'sqlite']].includes(activeWorkspace);
  const workspaceNavigation = [
    ['overview', 'Overview', 'folderSearch'],
    ['cases', 'Case Management', 'folderSearch'],
    ['evidence', 'Evidence Locker', 'folder'],
    ['exif', 'EXIF Analysis', 'camera'],
    ['registry', 'Windows Registry', 'database'],
    ['pcap', 'PCAP Analysis', 'network'],
    ['sqlite', 'SQLite Analysis', 'database'],
    ['timeline', 'Timeline', 'activity'],
    ['reports', 'Reports', 'fileText'],
    ['copilot', 'AI Copilot', 'sparkles'],
  ];
  const moduleCards = [
    { id: 'cases', title: 'Case Management', description: 'Edit case details, review status, and register for team access.', icon: 'folderSearch' },
    { id: 'evidence', title: 'Evidence Locker', description: 'Securely browse evidence, integrity details, and custody history.', icon: 'folder' },
    { id: 'exif', title: 'EXIF Analysis', description: 'Review image metadata and document analyst validation.', icon: 'camera' },
    { id: 'registry', title: 'Registry Analysis', description: 'Inspect Windows registry hives and extracted artifacts.', icon: 'database' },
    { id: 'pcap', title: 'PCAP Analysis', description: 'Analyze network packets, endpoints, and connections.', icon: 'network' },
    { id: 'sqlite', title: 'SQLite Analysis', description: 'Review database schemas, records, and timestamp candidates.', icon: 'database' },
    { id: 'timeline', title: 'Timeline', description: 'Correlate case events while preserving timestamp certainty.', icon: 'activity' },
    { id: 'reports', title: 'Reports', description: 'Prepare and export a reviewable investigation report.', icon: 'fileText' },
    { id: 'copilot', title: 'AI Copilot', description: 'Ask evidence-grounded questions with approved, cited facts.', icon: 'sparkles' },
  ];

  useEffect(() => {
    let active = true;
    if (!selectedRecord) {
      setCustodyChainValid(true);
      return () => { active = false; };
    }
    verifyCustody(selectedRecord.custody)
      .then((valid) => { if (active) setCustodyChainValid(valid); })
      .catch(() => { if (active) setCustodyChainValid(false); });
    return () => { active = false; };
  }, [selectedRecord]);

  useEffect(() => {
    setExifValidationStatus(selectedRecord?.exifValidation?.status || 'NEEDS REVIEW');
    setExifAnalyst(selectedRecord?.exifValidation?.analyst || '');
    setExifNotes(selectedRecord?.exifValidation?.notes || '');
    setExifArtifactReferences(selectedRecord?.exifValidation?.artifactReferences?.join('\n') || '');
    setRegistryReport(selectedRecord?.registryAnalysis?.report || null);
    setRegistryValidationStatus(selectedRecord?.registryAnalysis?.status || 'NEEDS REVIEW');
    setRegistryAnalyst(selectedRecord?.registryAnalysis?.analyst || '');
    setRegistryNotes(selectedRecord?.registryAnalysis?.notes || '');
    setRegistryArtifactReferences(selectedRecord?.registryAnalysis?.artifactReferences?.join('\n') || '');
    setPcapReport(selectedRecord?.pcapAnalysis?.report || null);
    setPcapValidationStatus(selectedRecord?.pcapAnalysis?.status || 'NEEDS REVIEW');
    setPcapAnalyst(selectedRecord?.pcapAnalysis?.analyst || '');
    setPcapNotes(selectedRecord?.pcapAnalysis?.notes || '');
    setPcapArtifactReferences(selectedRecord?.pcapAnalysis?.artifactReferences?.join('\n') || '');
    setSqliteReport(selectedRecord?.sqliteAnalysis?.report || null);
    setSqliteValidationStatus(selectedRecord?.sqliteAnalysis?.status || 'NEEDS REVIEW');
    setSqliteAnalyst(selectedRecord?.sqliteAnalysis?.analyst || '');
    setSqliteNotes(selectedRecord?.sqliteAnalysis?.notes || '');
    setSqliteArtifactReferences(selectedRecord?.sqliteAnalysis?.artifactReferences?.join('\n') || '');
  }, [selectedRecord]);

  const availableCases = useMemo(
    () => [...new Set([...cases, ...(caseId ? [caseId] : [])])].sort(),
    [cases, caseId],
  );

  useEffect(() => {
    if (!caseDropdownOpen && !casePopupOpen) return undefined;
    const handlePointerDown = (event) => {
      if (caseDropdownOpen && caseDropdownRef.current && !caseDropdownRef.current.contains(event.target)) {
        setCaseDropdownOpen(false);
      }
    };
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        if (caseDropdownOpen) setCaseDropdownOpen(false);
        if (casePopupOpen) setCasePopupOpen(false);
      }
    };
    document.addEventListener('mousedown', handlePointerDown);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [caseDropdownOpen, casePopupOpen]);

  const selectCaseFromDropdown = (selectedCase) => {
    const normalized = selectedCase.trim();
    if (!normalized || caseDetailsBusy) return;
    setError('');
    setNotice('');
    if (normalized !== caseId) setCaseDetails(null);
    setCaseId(normalized);
    setCaseInput(normalized);
    setCaseDropdownOpen(false);
    setCasePopupOpen(true);
  };

  const openCase = (event) => {
    event.preventDefault();
    const normalized = caseInput.trim();
    if (!normalized || caseDetailsBusy) return;
    setError('');
    setNotice('');
    if (normalized !== caseId) setCaseDetails(null);
    setCaseId(normalized);
    setCaseInput(normalized);
    navigateToWorkspace('cases');
  };

  const saveActiveCaseDetails = async (event) => {
    event.preventDefault();
    if (!db || !caseDetails || !caseId) return;
    setCaseDetailsBusy(true);
    setError('');
    setNotice('');
    try {
      const savedDetails = await saveCaseDetails(db, { ...caseDetails, caseId });
      setCaseDetails(savedDetails);
      setCases(await getCases(db));
      setNotice(`Details for ${caseId} saved.`);
    } catch (saveError) {
      setError(saveError.message || 'Case details could not be saved.');
    } finally {
      setCaseDetailsBusy(false);
    }
  };

  const registerActiveCase = async () => {
    const userId = authSession?.user?.id;
    if (!caseId || !userId || !supabase) {
      setTeamCaseRegistration({
        caseId,
        userId: userId || null,
        status: 'error',
        message: !caseId
          ? 'Open a local case before registering it.'
          : !userId
            ? 'Sign in with Supabase before registering a case.'
            : 'Supabase case registration is unavailable.',
      });
      return;
    }

    setTeamCaseRegistration({
      caseId,
      userId,
      status: 'registering',
      message: `Registering ${caseId} for team access…`,
    });
    try {
      const registeredCaseId = await registerLocalCase(supabase, caseId);
      const role = await getCaseMembershipRole(supabase, registeredCaseId, userId);
      setTeamCaseRegistration({
        caseId,
        userId,
        supabaseCaseId: registeredCaseId,
        status: 'registered',
        role,
        message: `${caseId} is registered for team access. No evidence, keys, or analysis data were uploaded.`,
      });
    } catch (registrationError) {
      setTeamCaseRegistration({
        caseId,
        userId,
        status: 'error',
        message: registrationError.message || 'The case could not be registered for team access.',
      });
    }
  };

  const prepareCopilotContext = async (overrideIds = null, overrideLiveAnalyses = null) => {
    const idsToUse = Array.isArray(overrideIds) ? overrideIds : copilotSelectedIds;
    const selected = activeRecords.filter((record) => idsToUse.includes(record.id));
    setCopilotBusy(true);
    setCopilotError('');
    setCopilotResponse(null);
    setCopilotApproved(false);
    try {
      const caseTimeline = createTimelineEvents(caseId, records, timelineIntegrity);
      const facts = await buildCopilotEvidenceContext(
        caseId,
        selected,
        async (record) => {
          await downloadEvidence(db, record.id);
          return true;
        },
        (custody) => verifyCustody(custody),
        {
          caseDetails,
          timelineEvents: caseTimeline,
          liveAnalyses: overrideLiveAnalyses || copilotLiveAnalyses,
        },
      );
      setCopilotFacts(facts);
      setCopilotApprovedFactIds(facts.map((fact) => fact.referenceId));
      return facts;
    } catch (copilotContextError) {
      setCopilotFacts([]);
      setCopilotApprovedFactIds([]);
      setCopilotError(copilotContextError.message || 'Could not prepare verified evidence facts.');
      return [];
    } finally {
      setCopilotBusy(false);
    }
  };

  const runCopilotToolkitScan = async () => {
    if (!db || !caseId || !activeRecords.length) {
      setCopilotError('Open a case with active evidence before running a toolkit scan.');
      return;
    }
    const targetIds = copilotSelectedIds.length
      ? copilotSelectedIds
      : activeRecords.slice(0, 25).map((record) => record.id);
    if (!copilotSelectedIds.length) setCopilotSelectedIds(targetIds);
    const targetRecords = activeRecords.filter((record) => targetIds.includes(record.id));
    setCopilotBusy(true);
    setCopilotError('');
    const nextLive = { ...copilotLiveAnalyses };
    const scanEntries = [];
    const scanResults = [];
    try {
      for (const record of targetRecords) {
        const blob = await downloadEvidence(db, record.id);
        const bytes = new Uint8Array(await blob.arrayBuffer());
        const custodyValid = await verifyCustody(record.custody).catch(() => false);
        const head4 = bytes.length >= 4 ? String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) : '';
        const head16 = bytes.length >= 16 ? new TextDecoder().decode(bytes.subarray(0, 16)) : '';
        const magic32 = bytes.length >= 4 ? new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true) : 0;
        const recordLive = { ...(nextLive[record.id] || {}) };
        const observedModules = [];
        const retrievedFacts = [];
        const explanations = [];

        retrievedFacts.push(
          { module: 'Inventory', label: 'File type & size', value: `${record.type || 'Unknown MIME'} · ${formatBytes(record.size)} (${record.size.toLocaleString()} bytes)` },
          { module: 'Integrity', label: 'SHA-256 hash', value: `${record.sha256} (verified match against encrypted vault payload)` },
          { module: 'Custody', label: 'Chain of custody', value: `${record.custody.length} event${record.custody.length === 1 ? '' : 's'} · ${custodyValid ? 'cryptographic chain verified' : 'verification warning'} · latest: ${record.custody.at(-1)?.action || 'None'} by ${record.custody.at(-1)?.actor || 'unknown'}` },
        );
        if (record.createdAt) {
          retrievedFacts.push({ module: 'Inventory', label: 'Vault intake time', value: formatDate(record.createdAt) });
        }
        if (record.lastModified) {
          retrievedFacts.push({ module: 'Inventory', label: 'File last modified', value: new Date(record.lastModified).toISOString() });
        }
        if (record.dimensions) {
          retrievedFacts.push({ module: 'Inventory', label: 'Image dimensions', value: record.dimensions });
        }
        if (record.pdfVersion) {
          retrievedFacts.push({ module: 'Inventory', label: 'PDF version', value: record.pdfVersion });
        }

        explanations.push(
          custodyValid
            ? `Cryptographic integrity confirmed: "${record.name}" matches its stored SHA-256 fingerprint and maintains an unbroken ${record.custody.length}-event Chain of Custody.`
            : `Custody attention needed: "${record.name}" passed SHA-256 payload verification, but its Chain of Custody requires manual review before relying on continuity.`,
        );

        let exifData = record.exif || recordLive.exif || null;
        if (!exifData && (String(record.type || '').startsWith('image/') || /\.(jpe?g|tiff?)$/i.test(record.name))) {
          const parsedExif = extractExifMetadata(bytes);
          if (parsedExif && Object.keys(parsedExif).length > 0) {
            exifData = parsedExif;
            recordLive.exif = parsedExif;
          }
        }
        if (exifData && Object.keys(exifData).length > 0) {
          const exifEntries = Object.entries(exifData);
          observedModules.push(`EXIF (${exifEntries.length} fields)`);
          exifEntries.slice(0, 8).forEach(([field, val]) => {
            retrievedFacts.push({ module: 'EXIF', label: exifLabels[field] || field, value: String(val) });
          });
          const hasGps = exifEntries.some(([k]) => k.toLowerCase().includes('gps'));
          const hasDevice = exifData.make || exifData.model;
          const hasDate = exifData.dateTimeOriginal || exifData.dateTime;
          explanations.push(
            `EXIF metadata retrieved (${exifEntries.length} fields): ${hasDevice ? `captures device identifiers (${[exifData.make, exifData.model].filter(Boolean).join(' ')})` : 'no camera make/model recorded'}${hasDate ? `, original capture timestamp "${exifData.dateTimeOriginal || exifData.dateTime}" (verify timezone offset—EXIF timestamps are typically local camera time)` : ''}${hasGps ? ', and embedded GPS coordinates suitable for geolocation corroboration' : ''}.`,
          );
        }

        let regReport = record.registryAnalysis?.report || recordLive.registryAnalysis?.report || null;
        if (!regReport && head4 === 'regf') {
          try {
            regReport = parseRegistryHive(bytes, record.name);
            recordLive.registryAnalysis = { report: regReport, status: 'NEEDS REVIEW', analyst: 'AI Copilot Toolkit Scan', notes: 'Live read-only REGF hive inspection.', artifactReferences: [], sourceSha256: record.sha256 };
          } catch (scanErr) {
            scanEntries.push(`${record.name}: Registry scan warning — ${scanErr.message}`);
            explanations.push(`Windows Registry parser reported a warning while inspecting this REGF hive: ${scanErr.message}.`);
          }
        }
        if (regReport) {
          const artifacts = regReport.artifacts || [];
          observedModules.push(`Registry (${artifacts.length} artifacts)`);
          artifacts.slice(0, 6).forEach((item) => {
            const preview = (item.values || []).slice(0, 3).map((v) => `${v.name}=${typeof v.data === 'object' ? JSON.stringify(v.data) : String(v.data)}`).join('; ');
            retrievedFacts.push({ module: 'Windows Registry', label: `${item.type} · ${item.keyPath}`, value: preview || 'Key present' });
          });
          const categories = [...new Set(artifacts.map((a) => a.type))].slice(0, 4).join(', ');
          explanations.push(
            `Windows Registry REGF hive identified (${artifacts.length} extracted artifact${artifacts.length === 1 ? '' : 's'}${categories ? ` covering ${categories}` : ''}). Registry entries establish system configuration, persistence mechanisms, user activity, or connected devices and should be cross-checked against timeline timestamps.`,
          );
        }

        let pcapReport = record.pcapAnalysis?.report || recordLive.pcapAnalysis?.report || null;
        if (!pcapReport && ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a].includes(magic32) || /\.(pcap|pcapng|cap)$/i.test(record.name))) {
          try {
            pcapReport = parsePcap(bytes, record.name);
            recordLive.pcapAnalysis = { report: pcapReport, status: 'NEEDS REVIEW', analyst: 'AI Copilot Toolkit Scan', notes: 'Live read-only PCAP inspection.', artifactReferences: [], sourceSha256: record.sha256 };
          } catch (scanErr) {
            scanEntries.push(`${record.name}: PCAP scan warning — ${scanErr.message}`);
            explanations.push(`PCAP parser reported a warning while inspecting this packet capture: ${scanErr.message}.`);
          }
        }
        if (pcapReport) {
          const conns = pcapReport.connections || [];
          const leads = pcapReport.leads || [];
          observedModules.push(`PCAP (${conns.length} connections, ${leads.length} leads)`);
          conns.slice(0, 5).forEach((c) => {
            retrievedFacts.push({
              module: 'PCAP',
              label: `${c.protocol} ${c.endpointA} ↔ ${c.endpointB}`,
              value: `${c.packets} packets (${formatBytes(c.bytes || 0)}) · ${c.firstSeen || 'time unknown'} → ${c.lastSeen || 'time unknown'}`,
            });
          });
          leads.slice(0, 4).forEach((l) => {
            retrievedFacts.push({
              module: 'PCAP Lead',
              label: l.indicator || 'Network indicator',
              value: `${l.sourceIp || '?'} → ${l.destinationIp || '?'}: ${l.note || l.classification || 'Requires analyst verification'}`,
            });
          });
          explanations.push(
            `Network capture analyzed (${pcapReport.packetCount ?? pcapReport.packets?.length ?? 0} packets across ${conns.length} connection${conns.length === 1 ? '' : 's'} and ${leads.length} investigative lead${leads.length === 1 ? '' : 's'}). ${leads.length ? 'Flagged network leads require manual endpoint attribution and packet-level verification in the PCAP module.' : 'Connection metadata provides concrete endpoint communication windows for timeline correlation.'}`,
          );
        }

        let sqliteReport = record.sqliteAnalysis?.report || recordLive.sqliteAnalysis?.report || null;
        if (!sqliteReport && head16 === 'SQLite format 3\0') {
          try {
            sqliteReport = await analyzeSqlite(bytes, record.name);
            recordLive.sqliteAnalysis = { report: sqliteReport, status: 'NEEDS REVIEW', analyst: 'AI Copilot Toolkit Scan', notes: 'Live read-only SQLite inspection.', artifactReferences: [], sourceSha256: record.sha256 };
          } catch (scanErr) {
            scanEntries.push(`${record.name}: SQLite scan warning — ${scanErr.message}`);
            explanations.push(`SQLite parser reported a warning while inspecting this database: ${scanErr.message}.`);
          }
        }
        if (sqliteReport) {
          const tables = sqliteReport.tables || [];
          observedModules.push(`SQLite (${sqliteReport.tableCount ?? tables.length} tables, ${sqliteReport.recordCount ?? 0} rows)`);
          tables.slice(0, 6).forEach((t) => {
            const tsCount = (t.timestampFields || []).length;
            retrievedFacts.push({
              module: 'SQLite',
              label: `Table ${t.name}`,
              value: `${(t.columns || []).length} columns, ${t.rowCount ?? (t.records || []).length} rows${tsCount ? `, ${tsCount} timestamp column${tsCount === 1 ? '' : 's'}` : ''}`,
            });
          });
          explanations.push(
            `SQLite database inspected (${sqliteReport.tableCount ?? tables.length} table${(sqliteReport.tableCount ?? tables.length) === 1 ? '' : 's'}, ${sqliteReport.recordCount ?? 0} sampled/indexed rows). Structured application tables and candidate timestamp fields can reconstruct user actions, messaging, or browser history after verifying column encodings in SQLite Analysis.`,
          );
        }

        if (!observedModules.length) {
          explanations.push(
            `No specialized EXIF, Registry, PCAP, or SQLite binary structure was detected in "${record.name}". Its file metadata, cryptographic hash, intake timestamps, and Chain of Custody logs have been extracted as verified baseline facts for timeline correlation and custody auditing.`,
          );
        }

        nextLive[record.id] = recordLive;
        scanEntries.push(`${record.name}: SHA-256 verified · ${record.custody.length} custody logs · ${observedModules.join(', ') || 'Inventory & custody logs'}`);
        scanResults.push({
          id: record.id,
          name: record.name,
          type: record.type || 'Unknown file',
          size: record.size,
          sha256: record.sha256,
          custodyValid,
          custodyCount: record.custody.length,
          modules: observedModules,
          facts: retrievedFacts,
          explanations,
        });
      }
      setCopilotLiveAnalyses(nextLive);
      setCopilotToolkitScanLog(scanEntries);
      setCopilotToolkitScanResults({
        caseId,
        scannedAt: new Date().toISOString(),
        items: scanResults,
      });
      await prepareCopilotContext(targetIds, nextLive);
    } catch (toolkitError) {
      setCopilotError(toolkitError.message || 'Toolkit observatory scan failed.');
    } finally {
      setCopilotBusy(false);
    }
  };

  const selectAllCaseRecordsForCopilot = async () => {
    const allIds = activeRecords.slice(0, 25).map((record) => record.id);
    setCopilotSelectedIds(allIds);
    await prepareCopilotContext(allIds);
  };

  const verifyCaseInvestigator = async () => {
    if (!supabaseConfigured) return true;
    const userId = authSession?.user?.id;
    if (!userId || !activeCaseRegistration?.supabaseCaseId || !supabase) return false;
    const role = await getCaseMembershipRole(supabase, activeCaseRegistration.supabaseCaseId, userId);
    setTeamCaseRegistration((current) => current?.caseId === caseId && current?.userId === userId
      ? { ...current, role }
      : current);
    return ['admin', 'investigator'].includes(role);
  };

  const openArchivedEvidence = async () => {
    setError('');
    if (!canManageCaseEvidence) {
      setError('Archived evidence is available only to case Admins and Investigators.');
      return;
    }
    try {
      if (!await verifyCaseInvestigator()) {
        setError('Your case membership does not authorize archived evidence review.');
        return;
      }
      setEvidenceListView('archived');
      if (!selectedRecord?.archivedAt) setSelectedId(archivedRecords[0]?.id ?? null);
    } catch (authorizationError) {
      setError(authorizationError.message || 'Case authorization could not be verified.');
    }
  };

  const openEvidenceAction = (action) => {
    if (!selectedRecord || selectedRecord.archivedAt) return;
    if (!canManageCaseEvidence) {
      setError('Sign in and register this case with an Admin or Investigator role before managing evidence.');
      return;
    }
    setEvidenceAction(action);
    setEvidenceActionAnalyst(authSession?.user?.email || custodian);
    setEvidenceActionReason('');
    setReplacementFile(null);
    setError('');
  };

  const closeEvidenceAction = () => {
    if (busy) return;
    setEvidenceAction(null);
    setEvidenceActionReason('');
    setReplacementFile(null);
  };

  const confirmEvidenceAction = async (event) => {
    event.preventDefault();
    if (!db || !selectedRecord || selectedRecord.archivedAt || !evidenceAction) return;
    if (!canManageCaseEvidence) {
      setError('Case authorization is required to manage evidence.');
      return;
    }
    if (!evidenceActionAnalyst.trim() || !evidenceActionReason.trim()) {
      setError('Enter the analyst name and a reason before confirming this action.');
      return;
    }
    if (evidenceAction === 'replace' && !replacementFile) {
      setError('Choose a replacement evidence file before confirming.');
      return;
    }

    setBusy(true);
    setError('');
    setNotice('');
    try {
      if (!await verifyCaseInvestigator()) {
        throw new Error('Your case membership does not authorize evidence management.');
      }
      const options = {
        analyst: evidenceActionAnalyst,
        reason: evidenceActionReason,
        userId: authSession?.user?.id || null,
      };
      if (evidenceAction === 'replace') {
        const replacementId = await replaceEvidence(db, selectedRecord.id, { ...options, file: replacementFile });
        const updatedRecords = await getCaseRecords(db, caseId);
        setRecords(updatedRecords);
        setSelectedId(replacementId);
        setEvidenceListView('active');
        setCopilotSelectedIds((ids) => ids.filter((id) => id !== selectedRecord.id));
        setCopilotFacts([]);
        setCopilotApprovedFactIds([]);
        setCopilotApproved(false);
        setNotice(`Evidence replaced. New evidence ID: ${replacementId}. Original evidence remains archived with its hash and custody history.`);
      } else {
        await archiveEvidenceRecord(db, selectedRecord.id, options);
        setRecords(await getCaseRecords(db, caseId));
        setSelectedId(selectedRecord.id);
        setEvidenceListView('archived');
        setCopilotSelectedIds((ids) => ids.filter((id) => id !== selectedRecord.id));
        setCopilotFacts([]);
        setCopilotApprovedFactIds([]);
        setCopilotApproved(false);
        setNotice('Evidence removed from the active case view and archived. Original bytes, hash, and custody history were preserved.');
      }
      setEvidenceAction(null);
      setEvidenceActionReason('');
      setReplacementFile(null);
    } catch (actionError) {
      setError(actionError.message || 'The evidence action could not be completed.');
    } finally {
      setBusy(false);
    }
  };

  const askCopilot = async (event, presetQuestion = null, options = {}) => {
    if (event) event.preventDefault();
    const { forceApproved = false } = options || {};
    if (copilotUsesTeamBackend && !teamCaseRegistered) {
      setCopilotError('Register the open local case for team access before sending a Copilot request.');
      return;
    }
    if (!copilotApproved && !forceApproved) {
      setCopilotError('Review the structured facts and approve their transmission before asking the Copilot.');
      return;
    }
    if (forceApproved && !copilotApproved) setCopilotApproved(true);
    const requestQuestion = (typeof presetQuestion === 'string' ? presetQuestion : copilotQuestion).trim();
    if (!requestQuestion) {
      setCopilotError('Enter an investigation question.');
      return;
    }
    const factsToAnalyze = copilotSelectedFacts.length ? copilotSelectedFacts : copilotFacts;
    if (!factsToAnalyze.length) {
      setCopilotError('Load case records or run a Toolkit Scan before sending an investigation question.');
      return;
    }
    setCopilotBusy(true);
    setCopilotError('');
    setCopilotResponse(null);
    try {
      const caseTimeline = createTimelineEvents(caseId, records, timelineIntegrity);
      const toolkitSummary = {
        activeEvidenceCount: activeRecords.length,
        archivedEvidenceCount: archivedRecords.length,
        savedAnalysisCount,
        timelineEventCount: caseTimeline.length,
        toolkitScanLog: copilotToolkitScanLog,
      };
      const batches = partitionCopilotFacts(requestQuestion, factsToAnalyze, caseId);
      const responses = [];
      for (let index = 0; index < batches.length; index += 1) {
        const batch = batches[index];
        const request = makeCopilotQuestion(requestQuestion, batch, caseId);
        let result;
        try {
          result = await callCopilot({
            supabaseUrl: copilotUsesTeamBackend ? import.meta.env.VITE_SUPABASE_URL : '',
            publishableKey: copilotUsesTeamBackend ? import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY : '',
            accessToken: authSession?.access_token || '',
            action: request.action,
            payload: {
              caseNumber: caseId,
              caseDetails,
              toolkitSummary,
              timelineEvents: caseTimeline.slice(0, 100),
              question: request.question,
              facts: request.facts,
            },
          });
        } catch (batchError) {
          throw new Error(`Copilot request batch ${index + 1} of ${batches.length} failed: ${batchError.message || 'AI service request failed.'}`, { cause: batchError });
        }
        responses.push(validateCopilotResponse(result, batch));
      }
      const response = combineCopilotResponses(responses);
      setCopilotLatestQuestion(requestQuestion);
      setCopilotResponse(response);
      setCopilotConversation((messages) => [
        ...messages,
        { id: messages.length + 1, question: requestQuestion, response },
      ]);
      if (!presetQuestion) setCopilotQuestion('');

      if (autoDocumentCopilot && db && copilotSelectedFacts.length) {
        try {
          const finding = makeCopilotFinding(response, requestQuestion, copilotSelectedFacts, 'copilot');
          await saveCopilotFinding(db, copilotSelectedFacts[0].evidenceId, finding);
          setRecords(await getCaseRecords(db, caseId));
          setNotice('AI analysis documented in the encrypted case vault as NEEDS REVIEW. Custodian/investigator verification is required.');
        } catch {
          // User can still manually save via button if auto-document fails.
        }
      }
    } catch (copilotRequestError) {
      setCopilotError(copilotRequestError.message || 'AI Copilot request failed.');
    } finally {
      setCopilotBusy(false);
    }
  };

  const saveCurrentCopilotFinding = async () => {
    const selectedFacts = copilotFacts.filter((fact) => copilotApprovedFactIds.includes(fact.referenceId));
    if (!copilotResponse || !selectedFacts.length) return;
    setCopilotBusy(true);
    setCopilotError('');
    try {
      const finding = makeCopilotFinding(copilotResponse, copilotLatestQuestion, selectedFacts, 'copilot');
      await saveCopilotFinding(db, selectedFacts[0].evidenceId, finding);
      setRecords(await getCaseRecords(db, caseId));
      setNotice('Copilot finding saved as NEEDS REVIEW. Custodian/investigator verification is required before treating claims as verified.');
    } catch (saveError) {
      setCopilotError(saveError.message || 'Copilot finding could not be saved.');
    } finally {
      setCopilotBusy(false);
    }
  };

  const reviewCopilotFinding = async (record, finding, customReview = null) => {
    const review = customReview || copilotReviews[finding.id] || {};
    const verifierName = (review.analyst || custodian || authSession?.user?.email || '').trim();
    const targetCaseId = record.caseId || caseId;
    setCopilotBusy(true);
    setCopilotError('');
    try {
      if (!review.attested) {
        throw new Error('Custodian or investigator must check the verification attestation before signing off.');
      }
      if (!verifierName) {
        throw new Error('Enter the custodian or investigator name to verify this AI finding.');
      }
      const authorization = await callCopilot({
        supabaseUrl: copilotUsesTeamBackend ? import.meta.env.VITE_SUPABASE_URL : '',
        publishableKey: copilotUsesTeamBackend ? import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY : '',
        accessToken: authSession?.access_token || '',
        action: 'authorize_validation',
        payload: { caseNumber: targetCaseId, investigator: verifierName },
      });
      if (authorization.authorized !== true || !authorization.investigatorId) {
        throw new Error('Only an authorized custodian or case investigator may validate Copilot findings.');
      }
      const resolvedStatus = review.status || 'VERIFIED';
      await validateCopilotFinding(db, record.id, finding.id, {
        status: resolvedStatus,
        analyst: authorization.investigator || verifierName,
        investigatorId: authorization.investigatorId,
        notes: review.notes || '',
        independentMethod: review.independentMethod || '',
        authorized: true,
      });
      const updated = await getCaseRecords(db, targetCaseId);
      if (targetCaseId === caseId) setRecords(updated);
      if (targetCaseId === timelineCaseId) setTimelineRecords(updated);
      setNotice(`Custodian/investigator verification (${resolvedStatus}) and custody event recorded by ${authorization.investigator || verifierName}.`);
      return true;
    } catch (reviewError) {
      setCopilotError(reviewError.message || 'Finding validation could not be saved.');
      return false;
    } finally {
      setCopilotBusy(false);
    }
  };

  const appendVerifiedFindingToReport = (finding) => {
    const verifiedStatements = [
      ...(finding.objectiveConclusions || []),
      ...(finding.interpretations || []),
    ].map((claim) => `- ${claim.text} [${(claim.evidenceRefs || []).join(', ')}]`);
    const verifier = finding.validationHistory?.at(-1);
    const block = [
      `Verified AI Analysis (${verifier?.analyst || 'Investigator'} · ${verifier?.reviewedAt ? formatDate(verifier.reviewedAt) : 'Verified'}):`,
      ...verifiedStatements,
    ].join('\n');
    setReportConclusions((current) => (current.trim() ? `${current.trim()}\n\n${block}` : block));
    setNotice('Verified conclusions appended to the Final Investigation Report conclusions field.');
  };

  const downloadCopilotFindings = () => {
    const report = {
      format: 'ClueBox Odyssey AI Forensic Copilot Documentation Report',
      caseId,
      caseDetails,
      exportedAt: new Date().toISOString(),
      toolkitScanLog: copilotToolkitScanLog,
      notice: 'All AI-generated conclusions, analytic statements, connections, workflows, and timeline analyses remain unverified until signed off by a custodian or investigator.',
      findings: savedCopilotFindings.map(({ evidenceRecord, ...finding }) => ({
        ...finding,
        savedOnEvidenceId: evidenceRecord.id,
        filename: evidenceRecord.name,
        evidenceSha256: evidenceRecord.sha256,
      })),
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${caseId.replace(/[^\w.-]+/g, '-')}-copilot-documentation.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const generateAiTimelineAnalysis = async () => {
    if (!db || !timelineCaseId) return;
    const targetRecords = timelineRecords.filter((record) => !record.archivedAt);
    if (!targetRecords.length) {
      setAiTimelineError('Add or select active evidence records in this case before generating an AI timeline analysis.');
      return;
    }
    setAiTimelineBusy(true);
    setAiTimelineError('');
    try {
      const targetDetails = timelineCaseId === caseId ? caseDetails : await getCaseDetails(db, timelineCaseId);
      const facts = await buildCopilotEvidenceContext(
        timelineCaseId,
        targetRecords.slice(0, 25),
        async (record) => {
          await downloadEvidence(db, record.id);
          return true;
        },
        (custody) => verifyCustody(custody),
        {
          caseDetails: targetDetails,
          timelineEvents,
          liveAnalyses: timelineCaseId === caseId ? copilotLiveAnalyses : {},
        },
      );
      const question = 'Generate an AI-analyzed forensic version of the investigation timeline correlating all evidence metadata, custody logs, toolkit reports, and timestamps, identifying objective conclusions, cross-artifact connections, gaps/anomalies, and a verification workflow.';
      const result = await callCopilot({
        supabaseUrl: copilotUsesTeamBackend ? import.meta.env.VITE_SUPABASE_URL : '',
        publishableKey: copilotUsesTeamBackend ? import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY : '',
        accessToken: authSession?.access_token || '',
        action: 'analyze_timeline',
        payload: {
          caseNumber: timelineCaseId,
          caseDetails: targetDetails,
          question,
          facts,
          timelineEvents: timelineEvents.slice(0, 100),
        },
      });
      const validated = validateCopilotResponse(result, facts);
      const generatedAt = new Date().toISOString();
      const finding = makeCopilotFinding(validated, question, facts, 'timeline');
      await saveCopilotFinding(db, facts[0].evidenceId, finding);
      const refreshed = await getCaseRecords(db, timelineCaseId);
      setTimelineRecords(refreshed);
      if (timelineCaseId === caseId) setRecords(refreshed);
      setAiTimelineAnalysis({
        caseId: timelineCaseId,
        findingId: finding.id,
        generatedAt,
        response: validated,
        facts,
        sourceEventCount: timelineEvents.length,
      });
      setAiTimelineSavedFinding({
        evidenceId: facts[0].evidenceId,
        findingId: finding.id,
        status: 'NEEDS REVIEW',
        validationHistory: [],
      });
      setAiTimelineReview((current) => ({
        ...current,
        analyst: current.analyst || custodian || authSession?.user?.email || '',
        attested: false,
      }));
      setNotice('AI-analyzed timeline generated and documented in the case vault as NEEDS REVIEW. Custodian/investigator verification is required.');
    } catch (timelineAiErr) {
      setAiTimelineError(timelineAiErr.message || 'Could not generate AI-analyzed timeline.');
    } finally {
      setAiTimelineBusy(false);
    }
  };

  const verifyAiTimelineAnalysis = async (event) => {
    event.preventDefault();
    if (!aiTimelineSavedFinding) return;
    const targetRecord = timelineRecords.find((item) => item.id === aiTimelineSavedFinding.evidenceId);
    const targetFinding = targetRecord?.copilotFindings?.find((item) => item.id === aiTimelineSavedFinding.findingId);
    if (!targetRecord || !targetFinding) {
      setAiTimelineError('Could not locate the documented AI timeline record in the vault.');
      return;
    }
    setAiTimelineError('');
    const ok = await reviewCopilotFinding(targetRecord, targetFinding, aiTimelineReview);
    if (ok) {
      setAiTimelineSavedFinding((current) => current ? { ...current, status: aiTimelineReview.status } : current);
    } else {
      setAiTimelineError('Custodian/investigator verification failed. Check name, notes, verification method, and attestation.');
    }
  };

  const downloadAiTimelineReport = () => {
    if (!aiTimelineAnalysis) return;
    const targetRecord = aiTimelineSavedFinding
      ? timelineRecords.find((item) => item.id === aiTimelineSavedFinding.evidenceId)
      : null;
    const documentedFinding = targetRecord?.copilotFindings?.find((item) => item.id === aiTimelineSavedFinding?.findingId);
    const payload = {
      format: 'ClueBox Odyssey AI-Analyzed Investigation Timeline Report',
      caseId: aiTimelineAnalysis.caseId,
      generatedAt: aiTimelineAnalysis.generatedAt,
      verificationStatus: documentedFinding?.validationStatus || aiTimelineSavedFinding?.status || 'NEEDS REVIEW',
      verificationHistory: documentedFinding?.validationHistory || [],
      sourceTimelineEventCount: aiTimelineAnalysis.sourceEventCount,
      aiAnalysis: aiTimelineAnalysis.response,
      sourceTimelineEvents: timelineEvents,
    };
    const safeCaseId = (aiTimelineAnalysis.caseId || 'case').replace(/[^\w.-]+/g, '-');
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safeCaseId}-ai-analyzed-timeline-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const jumpToWorkflowModule = (moduleLabel) => {
    const normalized = String(moduleLabel || '').toLowerCase();
    if (normalized.includes('exif')) navigateToWorkspace('exif');
    else if (normalized.includes('registry')) navigateToWorkspace('registry');
    else if (normalized.includes('pcap') || normalized.includes('network')) navigateToWorkspace('pcap');
    else if (normalized.includes('sqlite') || normalized.includes('database')) navigateToWorkspace('sqlite');
    else if (normalized.includes('timeline')) navigateToWorkspace('timeline');
    else if (normalized.includes('report')) navigateToWorkspace('reports');
    else if (normalized.includes('case')) navigateToWorkspace('cases');
    else navigateToWorkspace('evidence');
  };

  const downloadTimeline = (format) => {
    const safeCaseId = timelineCaseId.replace(/[^\w.-]+/g, '-') || 'case';
    const data = format === 'csv'
      ? timelineToCsv(filteredTimelineEvents)
      : JSON.stringify({
        format: 'ForensiAI Investigation Timeline',
        caseId: timelineCaseId,
        exportedAt: new Date().toISOString(),
        events: filteredTimelineEvents,
      }, null, 2);
    const mimeType = format === 'csv' ? 'text/csv' : 'application/json';
    const extension = format === 'csv' ? 'csv' : 'json';
    const url = URL.createObjectURL(new Blob([data], { type: mimeType }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safeCaseId}-timeline.${extension}`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const downloadInvestigationReport = async (format = 'json') => {
    if (!timelineCaseId) return;
    setReportBusy(true);
    setReportError('');
    setReportNotice('');
    try {
      const integrity = {};
      await Promise.all(timelineRecords.map(async (record) => {
        let sha256 = 'SHA-256 verification failed';
        let custody = false;
        try {
          await downloadEvidence(db, record.id);
          sha256 = 'SHA-256 verified';
        } catch (verificationError) {
          sha256 = `FAILED: ${verificationError.message || 'Evidence integrity could not be verified.'}`;
        }
        try {
          custody = await verifyCustody(record.custody);
        } catch {
          custody = false;
        }
        integrity[record.id] = {
          sha256,
          custody: custody ? 'VERIFIED' : 'FAILED OR UNVERIFIABLE',
          custodyValid: custody,
        };
      }));
      const reportTimeline = createTimelineEvents(
        timelineCaseId,
        timelineRecords,
        Object.fromEntries(Object.entries(integrity).map(([id, value]) => [id, { custody: value.custodyValid }])),
      );
      const report = createInvestigationReport({
        caseId: timelineCaseId,
        records: timelineRecords,
        timelineEvents: reportTimeline,
        integrity,
        summary: reportSummary,
        conclusions: reportConclusions,
      });
      const safeCaseId = timelineCaseId.replace(/[^\w.-]+/g, '-') || 'case';
      const isPdf = format === 'pdf';
      const blob = isPdf
        ? await import('./InvestigationReportPdf').then(({ generateInvestigationPdf }) => (
          generateInvestigationPdf(report, caseDetails?.leadInvestigator || '')
        ))
        : new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${safeCaseId}-investigation-report.${isPdf ? 'pdf' : 'json'}`;
      link.click();
      URL.revokeObjectURL(url);
      setReportNotice(
        `${isPdf ? 'PDF' : 'JSON'} investigation report exported locally. `
        + 'Integrity failures, unverified leads, ambiguous times, and limitations are identified in the report.',
      );
    } catch (reportBuildError) {
      setReportError(reportBuildError.message || 'The investigation report could not be generated.');
    } finally {
      setReportBusy(false);
    }
  };

  const submitAuth = async (event) => {
    event.preventDefault();
    if (!supabase) return;
    setAuthBusy(true);
    setAuthError('');
    setAuthMessage('');
    try {
      const result = authMode === 'signUp'
        ? await supabase.auth.signUp({ email: authEmail.trim(), password: authPassword })
        : await supabase.auth.signInWithPassword({ email: authEmail.trim(), password: authPassword });
      if (result.error) throw result.error;
      if (authMode === 'signUp' && !result.data.session) {
        setAuthMessage('Check your email to confirm the new account, then sign in.');
        setAuthMode('signIn');
        setAuthPassword('');
        setAuthPasswordVisible(false);
      } else {
        if (result.data.session) {
          setAuthSession(result.data.session);
          setWelcomeVisible(false);
        }
        setAuthPanelOpen(false);
        setAuthPassword('');
        setAuthPasswordVisible(false);
      }
    } catch (authIssue) {
      setAuthError(authIssue.message || 'Authentication failed.');
    } finally {
      setAuthBusy(false);
    }
  };

  const signOut = async () => {
    if (!supabase) return;
    const { error: signOutError } = await supabase.auth.signOut();
    if (signOutError) setAuthError(signOutError.message);
    else {
      setAuthSession(null);
      setWelcomeVisible(true);
      setAuthPanelOpen(false);
    }
  };

  const enterClueBoxOdyssey = () => {
    setAuthPanelOpen(false);
    if (!supabaseConfigured || authSession) {
      setWelcomeVisible(false);
      return;
    }
    openLandingAuth('signIn');
  };

  const handleFiles = async (fileList) => {
    const files = Array.from(fileList || []);
    if (!files.length || !db || !caseId) return;
    if (!custodian.trim()) {
      setError('Enter the custodian name before adding evidence.');
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    try {
      for (const file of files) {
        await saveEvidence(db, { file, caseId, custodian: custodian.trim() });
      }
      const updatedRecords = await getCaseRecords(db, caseId);
      setRecords(updatedRecords);
      setSelectedId(updatedRecords[0]?.id ?? null);
      setEvidenceListView('active');
      setCases(await getCases(db));
      setNotice(`${files.length} ${files.length === 1 ? 'file' : 'files'} encrypted and added to ${caseId}.`);
    } catch (vaultError) {
      setError(vaultError.message || 'The evidence could not be secured.');
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = '';
    }
  };

  const logCustodyEvent = async (event) => {
    event.preventDefault();
    if (selectedRecord?.archivedAt) {
      setError('Archived evidence is read-only and available for historical review.');
      return;
    }
    if (!selectedRecord || !custodian.trim()) {
      setError('Enter the custodian name to record a custody event.');
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await addCustodyEvent(db, selectedRecord.id, custodian.trim(), custodyAction);
      setRecords(await getCaseRecords(db, caseId));
      setNotice('Custody event recorded.');
    } catch (vaultError) {
      setError(vaultError.message || 'The custody event could not be recorded.');
    } finally {
      setBusy(false);
    }
  };

  const saveManualExifValidation = async (event) => {
    event.preventDefault();
    if (!selectedRecord || selectedRecord.archivedAt) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await saveExifValidation(db, selectedRecord.id, {
        status: exifValidationStatus,
        analyst: exifAnalyst,
        notes: exifNotes,
        artifactReferences: exifArtifactReferences.split(/\r?\n/),
      });
      setRecords(await getCaseRecords(db, caseId));
      setNotice('Manual EXIF validation saved.');
    } catch (validationError) {
      setError(validationError.message || 'Manual EXIF validation could not be saved.');
    } finally {
      setBusy(false);
    }
  };

  const analyzeRegistryHive = async () => {
    if (!selectedRecord || selectedRecord.archivedAt) return;
    setBusy(true);
    setRegistryReport(null);
    setError('');
    setNotice('');
    try {
      const evidence = await downloadEvidence(db, selectedRecord.id);
      const report = parseRegistryHive(await evidence.arrayBuffer(), selectedRecord.name);
      setRegistryReport(report);
      setRegistryValidationStatus('NEEDS REVIEW');
      setNotice(`Parsed ${report.keyCount.toLocaleString()} registry keys and found ${report.artifacts.length} supported artifacts.`);
    } catch (analysisError) {
      setError(analysisError.message || 'The registry hive could not be analyzed.');
    } finally {
      setBusy(false);
    }
  };

  const saveRegistryReport = async (event) => {
    event.preventDefault();
    if (!selectedRecord || selectedRecord.archivedAt || !registryReport) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await saveRegistryAnalysis(db, selectedRecord.id, {
        report: registryReport,
        status: registryValidationStatus,
        analyst: registryAnalyst,
        notes: registryNotes,
        artifactReferences: registryArtifactReferences.split(/\r?\n/),
      });
      setRecords(await getCaseRecords(db, caseId));
      setNotice('Registry analysis and custody report saved.');
    } catch (analysisError) {
      setError(analysisError.message || 'The registry analysis report could not be saved.');
    } finally {
      setBusy(false);
    }
  };

  const downloadRegistryReport = () => {
    if (!selectedRecord?.registryAnalysis) return;
    const analysis = selectedRecord.registryAnalysis;
    const report = {
      reportVersion: 1,
      evidence: {
        caseId: selectedRecord.caseId,
        name: selectedRecord.name,
        sha256: selectedRecord.sha256,
        size: selectedRecord.size,
      },
      analysis: {
        ...analysis.report,
        validation: {
          status: analysis.status,
          analyst: analysis.analyst,
          notes: analysis.notes,
          artifactReferences: analysis.artifactReferences,
          reviewedAt: analysis.reviewedAt,
        },
      },
      custody: {
        verified: custodyChainValid,
        events: selectedRecord.custody,
      },
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedRecord.name.replace(/[^\w.-]+/g, '-')}-registry-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const analyzePcap = async () => {
    if (!selectedRecord || selectedRecord.archivedAt) return;
    setBusy(true);
    setPcapReport(null);
    setError('');
    setNotice('');
    try {
      const evidence = await downloadEvidence(db, selectedRecord.id);
      const report = parsePcap(await evidence.arrayBuffer());
      setPcapReport(report);
      setPcapValidationStatus('NEEDS REVIEW');
      setNotice(`Parsed ${report.packetCount.toLocaleString()} IP packets and summarized ${report.connectionCount.toLocaleString()} connections.`);
    } catch (analysisError) {
      setError(analysisError.message || 'The PCAP capture could not be analyzed.');
    } finally {
      setBusy(false);
    }
  };

  const savePcapReport = async (event) => {
    event.preventDefault();
    if (!selectedRecord || selectedRecord.archivedAt || !pcapReport) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await savePcapAnalysis(db, selectedRecord.id, {
        report: pcapReport,
        status: pcapValidationStatus,
        analyst: pcapAnalyst,
        notes: pcapNotes,
        artifactReferences: pcapArtifactReferences.split(/\r?\n/),
      });
      setRecords(await getCaseRecords(db, caseId));
      setNotice('PCAP analysis and custody report saved.');
    } catch (analysisError) {
      setError(analysisError.message || 'The PCAP analysis report could not be saved.');
    } finally {
      setBusy(false);
    }
  };

  const downloadPcapReport = () => {
    if (!selectedRecord?.pcapAnalysis) return;
    const analysis = selectedRecord.pcapAnalysis;
    const report = {
      reportVersion: 1,
      evidence: {
        caseId: selectedRecord.caseId,
        name: selectedRecord.name,
        sha256: selectedRecord.sha256,
        size: selectedRecord.size,
      },
      analysis: {
        ...analysis.report,
        validation: {
          status: analysis.status,
          analyst: analysis.analyst,
          notes: analysis.notes,
          artifactReferences: analysis.artifactReferences,
          reviewedAt: analysis.reviewedAt,
        },
      },
      custody: {
        verified: custodyChainValid,
        events: selectedRecord.custody,
      },
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedRecord.name.replace(/[^\w.-]+/g, '-')}-pcap-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const analyzeSqliteDatabase = async () => {
    if (!selectedRecord || selectedRecord.archivedAt) return;
    setBusy(true);
    setSqliteReport(null);
    setError('');
    setNotice('');
    try {
      const evidence = await downloadEvidence(db, selectedRecord.id);
      const report = await analyzeSqlite(await evidence.arrayBuffer(), selectedRecord.name);
      setSqliteReport(report);
      setSqliteValidationStatus('NEEDS REVIEW');
      setNotice(`Analyzed ${report.tableCount} tables, ${report.viewCount} views, and ${report.recordCount.toLocaleString()} records.`);
    } catch (analysisError) {
      setError(analysisError.message || 'The SQLite database could not be analyzed.');
    } finally {
      setBusy(false);
    }
  };

  const saveSqliteReport = async (event) => {
    event.preventDefault();
    if (!selectedRecord || selectedRecord.archivedAt || !sqliteReport) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await saveSqliteAnalysis(db, selectedRecord.id, {
        report: sqliteReport,
        status: sqliteValidationStatus,
        analyst: sqliteAnalyst,
        notes: sqliteNotes,
        artifactReferences: sqliteArtifactReferences.split(/\r?\n/),
      });
      setRecords(await getCaseRecords(db, caseId));
      setNotice('SQLite analysis and custody report saved.');
    } catch (analysisError) {
      setError(analysisError.message || 'The SQLite analysis report could not be saved.');
    } finally {
      setBusy(false);
    }
  };

  const downloadSqliteReport = () => {
    if (!selectedRecord?.sqliteAnalysis) return;
    const analysis = selectedRecord.sqliteAnalysis;
    const report = {
      reportVersion: 1,
      evidence: {
        caseId: selectedRecord.caseId,
        name: selectedRecord.name,
        sha256: selectedRecord.sha256,
        size: selectedRecord.size,
      },
      analysis: {
        ...analysis.report,
        validation: {
          status: analysis.status,
          analyst: analysis.analyst,
          notes: analysis.notes,
          artifactReferences: analysis.artifactReferences,
          reviewedAt: analysis.reviewedAt,
        },
      },
      custody: {
        verified: custodyChainValid,
        events: selectedRecord.custody,
      },
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedRecord.name.replace(/[^\w.-]+/g, '-')}-sqlite-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownload = async () => {
    if (!selectedRecord) return;
    try {
      const blob = await downloadEvidence(db, selectedRecord.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = selectedRecord.name;
      link.click();
      URL.revokeObjectURL(url);
    } catch (vaultError) {
      setError(vaultError.message || 'The evidence could not be decrypted.');
    }
  };

  const renderAuthPanel = (className, formRef) => (
    <section ref={formRef} className={className} id="landing-auth" aria-label="Team account">
      <form onSubmit={submitAuth}>
        <div className="auth-panel-heading">
          <div><p className="eyebrow">FORENSIAI TEAM ACCESS</p><h2>{authMode === 'signUp' ? 'Create investigator account' : 'Sign in to your account'}</h2></div>
          <button type="button" className="auth-link" onClick={() => { setAuthMode(authMode === 'signUp' ? 'signIn' : 'signUp'); setAuthPasswordVisible(false); setAuthError(''); setAuthMessage(''); }}>
            {authMode === 'signUp' ? 'Use existing account' : 'Create account'}
          </button>
        </div>
        <div className="auth-fields">
          <label>Email<input type="email" autoComplete="email" required value={authEmail} onChange={(event) => setAuthEmail(event.target.value)} /></label>
          <div className="auth-password-group">
            <label htmlFor="auth-password">Password</label>
            <div className="auth-password-field">
              <input id="auth-password" type={authPasswordVisible ? 'text' : 'password'} autoComplete={authMode === 'signUp' ? 'new-password' : 'current-password'} minLength={8} required value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} />
              <button
                type="button"
                className="auth-password-toggle"
                aria-label={authPasswordVisible ? 'Hide password' : 'Show password'}
                aria-pressed={authPasswordVisible}
                onClick={() => setAuthPasswordVisible((visible) => !visible)}
              >
                <Icon name={authPasswordVisible ? 'eyeOff' : 'eye'} size={18} />
              </button>
            </div>
          </div>
          <button type="submit" className="button button-dark" disabled={authBusy}>{authBusy ? 'Please wait…' : authMode === 'signUp' ? 'Create account' : 'Sign in'}</button>
        </div>
        {authError && <p className="auth-feedback auth-feedback-error" role="alert">{authError}</p>}
        {authMessage && <p className="auth-feedback" role="status">{authMessage}</p>}
        <p className="auth-disclaimer">Your Supabase password is used only for sign-in. The separate vault passphrase is never sent to Supabase.</p>
      </form>
    </section>
  );

  if (!authReady) {
    return (
      <main className="auth-restore-screen" role="status" aria-live="polite">
        <ClueBoxLogo size={84} />
        <p>Restoring your ClueBox Odyssey session…</p>
      </main>
    );
  }

  if (welcomeVisible) {
    return (
      <div className="welcome-page">
        <header className="welcome-nav">
          <a className="welcome-brand" href="#welcome-top" aria-label="ClueBox Odyssey home">
            <ClueBoxLogo size={46} />
            <span>ClueBox <span>Odyssey</span></span>
          </a>
          <nav aria-label="Welcome navigation">
            <a href="#features">Features</a>
            <a href="#about">About</a>
            <button type="button" onClick={() => openLandingAuth('signIn')}>Sign In</button>
          </nav>
        </header>

        <main className="welcome-main" id="welcome-top">
          <section className="welcome-hero" aria-labelledby="welcome-title">
            <div className="welcome-hero-copy">
              <p className="welcome-kicker"><span /> EXPLORE THE DIGITAL UNKNOWN</p>
              <h1 id="welcome-title">Explore the<br /><span>Digital Unknown.</span></h1>
              <p className="welcome-subtitle">ClueBox Odyssey brings secure evidence management, forensic analysis, and AI-assisted investigations into one focused workspace.</p>
              <div className="welcome-actions">
                <button type="button" className="welcome-button welcome-button-primary" onClick={() => openLandingAuth('signUp')}>
                  Get Started <Icon name="chevron" size={18} />
                </button>
                <button type="button" className="welcome-button welcome-button-secondary" onClick={enterClueBoxOdyssey}>
                  Enter ClueBox Odyssey <Icon name="arrow" size={16} />
                </button>
                <a className="welcome-button welcome-button-secondary" href="#features">Explore Features</a>
              </div>
              <div className="welcome-trust-row">
                <span><Icon name="shield" size={16} /> Evidence integrity first</span>
                <span><Icon name="lock" size={16} /> Private local vault</span>
              </div>
            </div>
            <div className="welcome-hero-art">
              <div className="welcome-art-glow" />
              <div className="welcome-art-scene" role="img" aria-label="A glowing digital fingerprint inside a futuristic mystery box">
                <span className="welcome-orbit welcome-orbit-one" />
                <span className="welcome-orbit welcome-orbit-two" />
                <ClueBoxLogo className="welcome-scene-logo" size={220} decorative />
                <span className="welcome-scene-chip welcome-scene-chip-top">SIGNAL FOUND <i /></span>
                <span className="welcome-scene-chip welcome-scene-chip-bottom">EVIDENCE · CONTEXT · CLUES</span>
              </div>
              <span className="welcome-art-caption"><span /> FORENSIC SIGNALS · EVIDENCE · CONTEXT</span>
            </div>
          </section>

          {authPanelOpen && supabaseConfigured && renderAuthPanel('auth-panel landing-auth-panel', landingAuthRef)}
          {authPanelOpen && !supabaseConfigured && (
            <section ref={landingAuthRef} className="landing-auth-notice" id="landing-auth" role="alert">
              <Icon name="shield" size={20} />
              <div><strong>Team sign-in is not configured</strong><p>Connect this app to your Supabase project to sign in or create a team account. For local-only work, continue to the private vault below.</p></div>
            </section>
          )}
          <section className="welcome-features" id="features" aria-labelledby="welcome-features-title">
            <div className="welcome-section-heading">
              <p className="welcome-kicker"><span /> BUILT FOR INVESTIGATIONS</p>
              <h2 id="welcome-features-title">A clear view of every part of the case.</h2>
              <p>Purpose-built tools for secure evidence handling and structured analysis.</p>
            </div>
            <div className="welcome-feature-grid">
              {[
                ['folder', 'Evidence Locker', 'Encrypted local evidence, integrity hashes, and custody history.'],
                ['camera', 'Forensic Analysis', 'Dedicated EXIF, Registry, PCAP, and SQLite analysis tools.'],
                ['folderSearch', 'Case Management', 'Organize investigations and explicitly register cases for team access.'],
                ['activity', 'Timeline', 'Correlate forensic and custody events with timestamp context.'],
                ['fileText', 'Reports', 'Build reviewable investigation reports with citations and limitations.'],
                ['sparkles', 'AI Copilot', 'Explore approved structured facts with evidence-linked AI assistance.'],
              ].map(([icon, title, description]) => (
                <article className="welcome-feature-card" key={title}>
                  <span className={`welcome-feature-icon welcome-feature-icon-${icon}`}><Icon name={icon} size={22} /></span>
                  <h3>{title}</h3>
                  <p>{description}</p>
                  <span className="welcome-feature-line" />
                </article>
              ))}
            </div>
          </section>

          <section className="welcome-about" id="about" aria-labelledby="welcome-about-title">
            <div className="welcome-about-mark"><Icon name="shield" size={27} /></div>
            <div>
              <p className="welcome-kicker"><span /> DESIGNED FOR CAREFUL REVIEW</p>
              <h2 id="welcome-about-title">Evidence stays at the center.</h2>
              <p>ClueBox Odyssey brings secure local evidence handling, transparent analysis, and investigator review into one focused workspace. AI assistance is optional and grounded in facts that an investigator selects and approves.</p>
            </div>
          </section>
        </main>

        <footer className="welcome-footer">
          <a className="welcome-brand" href="#welcome-top" aria-label="ClueBox Odyssey home">
            <ClueBoxLogo size={40} />
            <span>ClueBox <span>Odyssey</span></span>
          </a>
          <span>Explore the Digital Unknown.</span>
          <a href="#about">About ClueBox Odyssey</a>
        </footer>
      </div>
    );
  }

  const activeToolkitScan = copilotToolkitScanResults?.caseId === caseId ? copilotToolkitScanResults : null;
  const unverifiedCopilotCount = savedCopilotFindings.filter((item) => item.validationStatus !== 'VERIFIED').length;

  const renderCopilotChatTab = ({ isMini = false, onSwitchTab }) => (
    <div className={`copilot-tab-pane copilot-chat-pane ${isMini ? 'copilot-chat-pane-mini' : 'copilot-chat-pane-full'}`}>
      <div className="copilot-chat-context-bar">
        <span className={`copilot-chat-context-pill ${copilotApproved && copilotSelectedFacts.length ? 'copilot-chat-context-ready' : ''}`}>
          {copilotSelectedFacts.length
            ? copilotApproved
              ? `${copilotSelectedFacts.length} verified facts approved`
              : `${copilotSelectedFacts.length} facts staged (approval needed)`
            : 'No evidence facts loaded yet'}
        </span>
        <div className="copilot-chat-context-actions">
          <button
            type="button"
            className="text-button"
            onClick={() => onSwitchTab('toolkit')}
          >
            {copilotSelectedFacts.length ? 'Manage facts & scan' : 'Open Toolkit Scan'}
          </button>
          {savedCopilotFindings.length > 0 && (
            <button
              type="button"
              className="text-button"
              onClick={() => onSwitchTab('verify')}
            >
              Verify ({unverifiedCopilotCount > 0 ? `${unverifiedCopilotCount} pending` : savedCopilotFindings.length})
            </button>
          )}
        </div>
      </div>

      <div className="copilot-chat-conversation" ref={isMini ? copilotConversationRef : undefined} aria-label="Copilot conversation">
        {!copilotConversation.length && (
          <div className="copilot-welcome">
            <span className="copilot-welcome-mark" aria-hidden="true">AI</span>
            <h3>Full-Toolkit Forensic Observatory</h3>
            <p>Use <strong>Toolkit &amp; Facts</strong> to scan evidence for extracted facts and plain-English explanations, then ask Copilot for objective conclusions, cross-artifact connections, viable next steps, and structured workflows.</p>
            {caseId && activeRecords.length > 0 && !copilotFacts.length && (
              <div className="copilot-welcome-actions">
                <button
                  type="button"
                  className="button button-accent"
                  disabled={copilotBusy}
                  onClick={async () => {
                    onSwitchTab('toolkit');
                    await runCopilotToolkitScan();
                  }}
                >
                  Run Toolkit Scan (Facts &amp; Explanations)
                </button>
              </div>
            )}
          </div>
        )}
        {copilotConversation.map(({ id, question, response }) => (
          <article className="copilot-chat-turn" key={id}>
            <div className="copilot-user-message"><span>You</span><p>{question}</p></div>
            <div className="copilot-assistant-message">
              <div className="copilot-result-heading"><h3>Copilot Forensic Analysis</h3><span>NEEDS CUSTODIAN VERIFICATION</span></div>
              {response.summary && (
                <p className="copilot-executive-summary">{response.summary}</p>
              )}
              {(response.insufficientEvidence || response.unsupportedClaims.length > 0) && (
                <p className="copilot-insufficient"><strong>INSUFFICIENT EVIDENCE — NEEDS REVIEW</strong> Unsupported or uncited AI claims are excluded below.</p>
              )}
              {[
                ['Objective Conclusions', response.objectiveConclusions || []],
                ['Analytic Statements & Interpretations', response.interpretations || []],
                ['Cross-Artifact & Log Connections', response.connections || []],
                ['Investigative Leads', response.investigativeLeads || []],
                ['Viable Next Steps & Recommendations', response.recommendations || []],
                ['Gaps, Anomalies & Limitations', response.gapsAndAnomalies || []],
              ].map(([heading, claims]) => (
                <section key={heading}>
                  <h4>{heading}</h4>
                  {claims.length ? claims.map((claim, index) => (
                    <article className="copilot-claim" key={`${heading}-${index}`}>
                      <p>{claim.text}</p>
                      <small>Evidence references: {claim.evidenceRefs.join(', ')}</small>
                    </article>
                  )) : <p className="copilot-empty">No supported items returned.</p>}
                </section>
              ))}
              {(response.workflow?.length > 0) && (
                <section>
                  <h4>Recommended Investigation Workflow</h4>
                  <ol className="copilot-workflow-list">
                    {response.workflow.map((step) => (
                      <li className="copilot-workflow-step" key={`${step.step}-${step.title}`}>
                        <div className="copilot-workflow-head">
                          <strong>Step {step.step}: {step.title}</strong>
                          <button
                            type="button"
                            className="copilot-module-jump"
                            onClick={() => jumpToWorkflowModule(step.module)}
                          >
                            {step.module} →
                          </button>
                        </div>
                        <p>{step.action}</p>
                        <small>Evidence references: {step.evidenceRefs.join(', ')}</small>
                      </li>
                    ))}
                  </ol>
                </section>
              )}
              {(response.analyzedTimeline?.length > 0) && (
                <section>
                  <h4>AI-Analyzed Timeline Highlights</h4>
                  <div className="copilot-timeline-highlights">
                    {response.analyzedTimeline.map((item, idx) => (
                      <article className="copilot-claim" key={`tl-${idx}`}>
                        <div className="copilot-workflow-head">
                          <strong>{item.timestamp}</strong>
                          <span className={`ai-sig-badge ai-sig-${item.significance.toLowerCase()}`}>{item.significance}</span>
                        </div>
                        <p><strong>{item.eventSummary}</strong> — {item.analysis}</p>
                        <small>Evidence references: {item.evidenceRefs.join(', ')}</small>
                      </article>
                    ))}
                  </div>
                </section>
              )}
              <details className="copilot-observed-details">
                <summary>Observed Evidence &amp; Logs ({response.observedEvidence.length})</summary>
                {response.observedEvidence.map((fact) => (
                  <article className="copilot-citation" key={fact.referenceId}>
                    <strong>{fact.referenceId} · {fact.caseId} / {fact.filename} · SHA-256 {fact.sha256}</strong>
                    <span>{fact.evidenceId} · {fact.module} · {fact.artifactType}: {fact.artifactReference}</span>
                    <span>Observed value: {fact.value}</span>
                    <small>Integrity: {fact.integrityStatus}; custody: {fact.custodyStatus}; human validation: {fact.validationStatus}</small>
                  </article>
                ))}
              </details>
              {response.unsupportedClaims.length > 0 && (
                <details className="copilot-unsupported">
                  <summary>Excluded unsupported claims ({response.unsupportedClaims.length})</summary>
                  <ul>{response.unsupportedClaims.map((claim, index) => <li key={index}>{claim.text} — {claim.reason}</li>)}</ul>
                </details>
              )}
              {response === copilotResponse && (
                <div className="copilot-result-actions">
                  <button type="button" className="button button-dark" onClick={saveCurrentCopilotFinding} disabled={copilotBusy}>Document &amp; Save as NEEDS REVIEW</button>
                  <button type="button" className="button button-dark" onClick={() => onSwitchTab('verify')}>Open Verification Gate</button>
                  <button
                    type="button"
                    className="button button-dark"
                    onClick={() => {
                      setTimelineViewMode('ai');
                      navigateToWorkspace('timeline');
                    }}
                  >
                    Open AI-Analyzed Timeline
                  </button>
                </div>
              )}
            </div>
          </article>
        ))}
        {copilotBusy && <p className="copilot-thinking" role="status">Processing forensic analysis (extended timeout active for thorough review)…</p>}
        {copilotError && <p className="copilot-error" role="alert">{copilotError}</p>}
      </div>

      {copilotFacts.length > 0 && copilotApproved && (
        <div className="copilot-quick-prompts" aria-label="Quick forensic analysis actions">
          {[
            ['Objective Conclusions', 'Synthesize all verified records, toolkit outputs, and custody logs into objective forensic conclusions with exact evidence citations.'],
            ['Cross-Artifact Connections', 'Identify all cross-artifact connections, shared timestamps, custody links, and correlations across the case records and logs.'],
            ['Workflow & Next Steps', 'Lay out a prioritized step-by-step forensic workflow and viable next steps across the ClueBox Odyssey toolkit modules.'],
            ['Audit Logs & Timeline', 'Audit all chain-of-custody logs, timestamp uncertainties, anomalies, and evidentiary gaps across the investigation timeline.'],
          ].map(([label, promptText]) => (
            <button
              key={label}
              type="button"
              className="copilot-quick-chip"
              disabled={copilotBusy || !copilotAccessReady}
              onClick={() => askCopilot(null, promptText)}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      <form
        className="copilot-question-form copilot-chat-composer"
        onSubmit={askCopilot}
        aria-label="Ask the AI Copilot"
      >
        <label htmlFor={isMini ? 'copilot-question' : 'copilot-workspace-question'}>Investigation question</label>
        <textarea
          ref={isMini ? copilotQuestionRef : undefined}
          id={isMini ? 'copilot-question' : 'copilot-workspace-question'}
          rows={isMini ? '2' : '3'}
          maxLength="2000"
          value={copilotQuestion}
          onChange={(event) => setCopilotQuestion(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
              event.preventDefault();
              event.currentTarget.form?.requestSubmit();
            }
          }}
          aria-describedby={isMini ? 'copilot-composer-help' : 'copilot-workspace-composer-help'}
          placeholder="Ask for objective conclusions, cross-record connections, timeline audit, or an investigation workflow…"
          required
        />
        <div className="copilot-composer-actions">
          <small id={isMini ? 'copilot-composer-help' : 'copilot-workspace-composer-help'}>
            {!copilotFacts.length
              ? 'Open Toolkit & Facts to scan evidence, then approve before sending. Ctrl/⌘ + Enter sends.'
              : !copilotApproved
                ? 'Approve selected facts in Toolkit & Facts before sending.'
                : copilotUsesTeamBackend && !teamCaseRegistered
                  ? 'Register the open local case for team access before sending.'
                  : !copilotConfigured
                    ? copilotAvailability
                    : 'Only approved structured facts & logs are analyzed. Extended 5-minute timeout enabled.'}
          </small>
          <button
            type="submit"
            className="button button-accent"
            disabled={copilotBusy || !caseId || !copilotApproved || !copilotApprovedFactIds.length || !copilotAccessReady}
          >
            {copilotBusy ? 'Analyzing…' : 'Send'}
          </button>
        </div>
      </form>
    </div>
  );

  const renderCopilotToolkitTab = ({ onSwitchTab }) => (
    <div className="copilot-tab-pane copilot-toolkit-pane">
      {copilotError && <p className="copilot-error" role="alert">{copilotError}</p>}
      {!caseId ? (
        <p className="copilot-empty">Open a case to grant Copilot observatory access to evidence, logs, and toolkit modules.</p>
      ) : (
        <>
          <div className="copilot-toolkit-bar">
            <button
              type="button"
              className="button button-accent"
              onClick={runCopilotToolkitScan}
              disabled={copilotBusy || !activeRecords.length}
            >
              {copilotBusy ? 'Scanning evidence & retrieving facts…' : 'Run Toolkit Scan (Facts & Explanations)'}
            </button>
            <button
              type="button"
              className="button button-dark"
              onClick={selectAllCaseRecordsForCopilot}
              disabled={copilotBusy || !activeRecords.length}
            >
              Load all records &amp; logs ({activeRecords.length})
            </button>
          </div>

          {activeToolkitScan && activeToolkitScan.items.length > 0 && (
            <div className="copilot-scan-results" aria-label="Toolkit scan retrieved facts and explanations">
              <div className="copilot-result-heading">
                <h3>Toolkit Scan: Retrieved Facts &amp; Explanations ({activeToolkitScan.items.length} file{activeToolkitScan.items.length === 1 ? '' : 's'})</h3>
                <span>Scanned {formatDate(activeToolkitScan.scannedAt)}</span>
              </div>
              <div className="copilot-scan-cards">
                {activeToolkitScan.items.map((item) => (
                  <article className="copilot-scan-card" key={`scan-card-${item.id}`}>
                    <div className="copilot-scan-card-head">
                      <div>
                        <strong>{item.name}</strong>
                        <small>{item.id} · {formatBytes(item.size)} · SHA-256 {item.sha256.slice(0, 16)}…</small>
                      </div>
                      <span className={`validation-status ${item.custodyValid ? 'validation-verified' : 'validation-needs-review'}`}>
                        {item.modules.length ? item.modules.join(' · ') : 'Baseline Metadata & Custody'}
                      </span>
                    </div>
                    <div className="copilot-scan-explanations">
                      <h4>Forensic Explanation</h4>
                      <ul>
                        {item.explanations.map((line, idx) => <li key={`exp-${item.id}-${idx}`}>{line}</li>)}
                      </ul>
                    </div>
                    <details className="copilot-scan-facts" open>
                      <summary>Retrieved Evidence Facts ({item.facts.length})</summary>
                      <dl>
                        {item.facts.map((f, idx) => (
                          <div className="copilot-scan-fact-row" key={`fact-${item.id}-${idx}`}>
                            <dt><span>{f.module}</span> {f.label}</dt>
                            <dd>{f.value}</dd>
                          </div>
                        ))}
                      </dl>
                    </details>
                  </article>
                ))}
              </div>
              {copilotFacts.length > 0 && (
                <div className="copilot-result-actions">
                  <button
                    type="button"
                    className="button button-accent"
                    disabled={copilotBusy || !copilotAccessReady}
                    onClick={async () => {
                      onSwitchTab('chat');
                      await askCopilot(
                        null,
                        'Provide a detailed forensic explanation of all retrieved toolkit scan facts across these evidence records, highlight cross-artifact connections and integrity/custody findings, and lay out a concrete verification workflow.',
                        { forceApproved: true },
                      );
                    }}
                  >
                    Approve &amp; Ask AI for Deep Explanation
                  </button>
                </div>
              )}
            </div>
          )}

          <details className="copilot-context" open={!activeToolkitScan}>
            <summary>Select Evidence Records ({copilotSelectedIds.length}/{activeRecords.length} selected)</summary>
            <fieldset className="copilot-evidence-select" disabled={copilotBusy}>
              <legend>Evidence, custody logs, and toolkit results — {caseId}</legend>
              {!activeRecords.length ? <p>No active evidence records are saved in this local case.</p> : activeRecords.map((record) => (
                <label key={record.id} className="copilot-evidence-option">
                  <input
                    type="checkbox"
                    checked={copilotSelectedIds.includes(record.id)}
                    onChange={(event) => {
                      setCopilotSelectedIds((ids) => event.target.checked
                        ? [...ids, record.id].slice(0, 25)
                        : ids.filter((id) => id !== record.id));
                      setCopilotFacts([]);
                      setCopilotApprovedFactIds([]);
                      setCopilotApproved(false);
                      setCopilotResponse(null);
                    }}
                  />
                  <span><strong>{record.name}</strong><small>{record.id} · SHA-256 {record.sha256.slice(0, 16)}… · {record.custody.length} custody logs</small></span>
                  <small>{[
                    (record.exif || copilotLiveAnalyses[record.id]?.exif) && 'EXIF',
                    (record.registryAnalysis || copilotLiveAnalyses[record.id]?.registryAnalysis) && 'Registry',
                    (record.pcapAnalysis || copilotLiveAnalyses[record.id]?.pcapAnalysis) && 'PCAP',
                    (record.sqliteAnalysis || copilotLiveAnalyses[record.id]?.sqliteAnalysis) && 'SQLite',
                  ].filter(Boolean).join(' · ') || 'Inventory & custody logs'}</small>
                </label>
              ))}
            </fieldset>
            <button type="button" className="button button-dark" onClick={() => prepareCopilotContext()} disabled={copilotBusy || !copilotSelectedIds.length}>
              {copilotBusy ? 'Verifying evidence & logs…' : 'Verify & stage selected facts'}
            </button>
          </details>

          {copilotFacts.length > 0 && (
            <div className="copilot-preview">
              <div className="copilot-result-heading">
                <h3>Staged Structured Facts &amp; Logs ({copilotApprovedFactIds.length}/{copilotFacts.length})</h3>
                <button type="button" className="text-button" onClick={() => onSwitchTab('chat')}>Go to Chat →</button>
              </div>
              <p>Original evidence bytes and encryption keys stay local. Approve checked facts below to enable AI chat analysis.</p>
              <label className="copilot-approval">
                <input type="checkbox" checked={copilotApproved} disabled={!copilotApprovedFactIds.length} onChange={(event) => setCopilotApproved(event.target.checked)} />
                I reviewed and approve granting AI Copilot observatory access to these checked structured facts and logs.
              </label>
              <label className="copilot-approval">
                <input type="checkbox" checked={autoDocumentCopilot} onChange={(event) => setAutoDocumentCopilot(event.target.checked)} />
                Automatically document every Copilot analysis in the encrypted case vault (as NEEDS REVIEW for custodian/investigator sign-off).
              </label>
              <p className="copilot-request-size" role="status" aria-live="polite">
                {copilotSelectedFacts.length
                  ? copilotQuestion.trim()
                    ? `${copilotSelectedFacts.length} selected facts will be sent in ${copilotRequestBatches.length} request${copilotRequestBatches.length === 1 ? '' : 's'}: ${copilotRequestBatches.map((batch) => `${getCopilotRequestSize(copilotQuestion, batch, caseId).toLocaleString()} bytes`).join(', ')} (maximum ${MAX_COPILOT_REQUEST_BYTES.toLocaleString()} bytes each).`
                    : `${copilotSelectedFacts.length} facts & logs selected and ready for analysis.`
                  : 'No facts selected. Choose the facts relevant to your question.'}
              </p>
              <details className="copilot-observed-details">
                <summary>Inspect individual staged facts ({copilotFacts.length})</summary>
                <ul className="copilot-fact-list">
                  {copilotFacts.map((fact) => (
                    <li key={fact.referenceId}>
                      <label className="copilot-fact-choice">
                        <input
                          type="checkbox"
                          checked={copilotApprovedFactIds.includes(fact.referenceId)}
                          onChange={(event) => {
                            setCopilotApprovedFactIds((ids) => event.target.checked
                              ? [...ids, fact.referenceId]
                              : ids.filter((id) => id !== fact.referenceId));
                            setCopilotApproved(false);
                            setCopilotResponse(null);
                          }}
                        />
                        <span>
                          <strong>{fact.referenceId} · {fact.module} / {fact.artifactType}</strong>
                          <code>{fact.filename} · {fact.evidenceId} · SHA-256 {fact.sha256} · {fact.artifactReference}</code>
                          <span>{fact.value}</span>
                          <small>{fact.integrityStatus}; {fact.custodyStatus}; validation: {fact.validationStatus}</small>
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              </details>
            </div>
          )}
        </>
      )}
    </div>
  );

  const renderCopilotVerifyTab = () => (
    <div className="copilot-tab-pane copilot-verify-pane">
      {copilotError && <p className="copilot-error" role="alert">{copilotError}</p>}
      <div className="copilot-result-heading">
        <h3>Documented AI Findings &amp; Verification Gate ({savedCopilotFindings.length})</h3>
        {savedCopilotFindings.length > 0 && (
          <button type="button" className="text-button" onClick={downloadCopilotFindings}>Download full AI documentation report</button>
        )}
      </div>
      {!savedCopilotFindings.length ? (
        <p className="copilot-empty">No AI analyses have been documented for this case yet. Run an AI Copilot query or generate an AI-Analyzed Timeline to document findings for custodian/investigator verification.</p>
      ) : (
        <div className="copilot-saved-findings">
          {savedCopilotFindings.map(({ evidenceRecord, ...finding }) => {
            const review = copilotReviews[finding.id] || {};
            const defaultVerifier = review.analyst ?? custodian ?? authSession?.user?.email ?? '';
            const isVerified = finding.validationStatus === 'VERIFIED';
            return (
              <article className="copilot-saved-finding" key={finding.id}>
                <div className="copilot-result-heading">
                  <strong>{finding.analysisType === 'timeline' ? '[AI Timeline] ' : ''}{finding.question}</strong>
                  <span className={`validation-status validation-${finding.validationStatus.toLowerCase().replaceAll(' ', '-')}`}>{finding.validationStatus}</span>
                </div>
                <p>
                  Documented with {finding.observedEvidence.length} verified facts/logs
                  {finding.objectiveConclusions?.length ? ` · ${finding.objectiveConclusions.length} conclusions` : ''}
                  {finding.connections?.length ? ` · ${finding.connections.length} connections` : ''}
                  {finding.workflow?.length ? ` · ${finding.workflow.length} workflow steps` : ''}.
                  {' '}Custodians/investigators must verify AI work before treating it as a confirmed finding.
                </p>
                {isVerified && (
                  <button
                    type="button"
                    className="text-button"
                    onClick={() => appendVerifiedFindingToReport(finding)}
                  >
                    Copy verified conclusions to Final Investigation Report
                  </button>
                )}
                <form
                  className="copilot-review-form"
                  onSubmit={(event) => {
                    event.preventDefault();
                    reviewCopilotFinding(evidenceRecord, finding, {
                      ...review,
                      status: review.status || 'VERIFIED',
                      analyst: defaultVerifier,
                    });
                  }}
                >
                  <label>Custodian / Investigator Name
                    <input
                      required
                      value={defaultVerifier}
                      placeholder="Enter verifying custodian or investigator name"
                      onChange={(event) => setCopilotReviews((all) => ({ ...all, [finding.id]: { ...all[finding.id], analyst: event.target.value } }))}
                    />
                  </label>
                  <label>Verification Status
                    <select value={review.status || 'VERIFIED'} onChange={(event) => setCopilotReviews((all) => ({ ...all, [finding.id]: { ...all[finding.id], status: event.target.value } }))}>
                      <option>VERIFIED</option><option>MISMATCH</option><option>NEEDS REVIEW</option>
                    </select>
                  </label>
                  <label>Verification Notes
                    <textarea required rows="2" placeholder="Document what was verified or disputed against raw artifacts" value={review.notes || ''} onChange={(event) => setCopilotReviews((all) => ({ ...all, [finding.id]: { ...all[finding.id], notes: event.target.value } }))} />
                  </label>
                  <label>Independent Verification Tool or Method
                    <input required placeholder="e.g. Manual SHA-256 check, EXIF inspection, REGF hive review" value={review.independentMethod || ''} onChange={(event) => setCopilotReviews((all) => ({ ...all, [finding.id]: { ...all[finding.id], independentMethod: event.target.value } }))} />
                  </label>
                  <label className="copilot-approval">
                    <input
                      type="checkbox"
                      checked={Boolean(review.attested)}
                      onChange={(event) => setCopilotReviews((all) => ({ ...all, [finding.id]: { ...all[finding.id], attested: event.target.checked } }))}
                    />
                    I attest as custodian/investigator that I independently verified this AI analysis against the underlying evidence and logs.
                  </label>
                  <button
                    type="submit"
                    className="button button-dark"
                    disabled={copilotBusy || !review.attested || !defaultVerifier.trim()}
                  >
                    Verify &amp; Record Custody Sign-Off
                  </button>
                </form>
                {finding.validationHistory?.map((entry, index) => (
                  <p className="copilot-validation-history" key={`${finding.id}-${index}`}>
                    {entry.status} by {entry.analyst} ({entry.investigatorId}) on {formatDate(entry.reviewedAt)} · {entry.independentMethod}
                  </p>
                ))}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );

  return (
    <div ref={appRootRef} className={`locker-app ${sidebarCollapsed ? 'locker-app-collapsed' : ''}`} data-active-workspace={activeWorkspace}>
      <aside className="command-sidebar" data-scroll-region="sidebar">
        <div className="sidebar-brand">
          <ClueBoxLogo className="sidebar-brand-logo" size={42} />
          <span className="sidebar-brand-copy">ClueBox <strong>Odyssey</strong><small>Explore the Digital Unknown.</small></span>
        </div>
        <button
          type="button"
          className="sidebar-toggle"
          aria-label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
          onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
        >
          <span aria-hidden="true">{sidebarCollapsed ? '›' : '‹'}</span>
          <span className="sidebar-toggle-label">{sidebarCollapsed ? 'Expand' : 'Collapse'}</span>
        </button>
        <p className="sidebar-group-label">INVESTIGATION</p>
        <nav className="sidebar-nav" aria-label="Forensic workspace navigation">
          {workspaceNavigation.map(([workspace, label, icon]) => (
            <button
              type="button"
              className={`sidebar-link ${activeWorkspace === workspace ? 'sidebar-link-active' : ''}`}
              data-workspace={workspace}
              key={workspace}
              aria-label={label}
              title={sidebarCollapsed ? label : undefined}
              aria-current={activeWorkspace === workspace ? 'page' : undefined}
              onClick={() => navigateToWorkspace(workspace)}
            >
              <span className="sidebar-link-icon" data-icon={icon} aria-hidden="true"><Icon name={icon} size={18} /></span>
              <span className="sidebar-link-label">{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-case">
          <span className="sidebar-case-indicator" />
          <span className="sidebar-case-copy"><small>ACTIVE CASE</small><strong>{caseId || 'No case selected'}</strong></span>
        </div>
      </aside>
      <div className="command-main">
        <header className="topbar">
        <div className="brand" aria-label="ClueBox Odyssey">
          <ClueBoxLogo size={34} />
          <span>ClueBox <span className="brand-light">Odyssey</span></span>
        </div>
        <div className="topbar-right">
          <span className="privacy-indicator"><span className="privacy-dot" /> {supabaseConfigured ? 'TEAM SIGN-IN CONFIGURED' : 'PRIVATE LOCAL VAULT'}</span>
          {supabaseConfigured && (authSession ? (
            <div className="auth-user"><span title={authSession.user.email}>{authSession.user.email}</span><button type="button" className="auth-link" onClick={signOut}>Sign out</button></div>
          ) : (
            <button type="button" className="auth-link auth-trigger" onClick={() => { setAuthPasswordVisible(false); setAuthError(''); setAuthMessage(''); setAuthPanelOpen((open) => !open); }}>
              {authPanelOpen ? 'Close sign in' : 'Team sign in'}
            </button>
          ))}
          <span className="topbar-divider" />
          <label className="custodian-field">
            <span>Custodian</span>
            <input value={custodian} onChange={(event) => setCustodian(event.target.value)} placeholder="Your name" aria-label="Custodian name" />
          </label>
        </div>
        </header>

      {supabaseConfigured && authPanelOpen && renderAuthPanel('auth-panel', null)}

      <main className="workspace" data-scroll-region="main-workspace" ref={workspaceRef}>
        <section className="page-heading">
          <div>
            <p className="eyebrow">FORENSIC OPERATIONS / {workspaces[activeWorkspace][0].toUpperCase()}</p>
            <h1>{workspaces[activeWorkspace][0]}</h1>
            <p className="heading-copy">{workspaces[activeWorkspace][1]}</p>
          </div>
          <div className="encryption-note"><Icon name="shield" size={17} /><span>AES-256 encrypted at rest</span></div>
        </section>

        <section className="case-toolbar" aria-label="Case selection">
          <form className="case-form" onSubmit={openCase}>
            <label htmlFor="case-id">CASE ID</label>
            <div className="case-input-wrap">
              <input ref={caseInputRef} id="case-id" value={caseInput} onChange={(event) => setCaseInput(event.target.value)} placeholder="Enter a case ID" list="saved-cases" />
              <datalist id="saved-cases">{cases.map((savedCase) => <option key={savedCase} value={savedCase} />)}</datalist>
            </div>
            <button type="submit" className="button button-dark" disabled={!db || !caseInput.trim() || caseDetailsBusy}>
              Open case <Icon name="arrow" size={16} />
            </button>
          </form>
          <div className="case-dropdown-wrap" ref={caseDropdownRef}>
            <button
              type="button"
              className="button button-dark case-dropdown-trigger"
              aria-haspopup="menu"
              aria-expanded={caseDropdownOpen}
              onClick={() => setCaseDropdownOpen((open) => !open)}
              disabled={!db}
            >
              Cases ({availableCases.length}) <Icon name="chevron" size={15} />
            </button>
            {caseDropdownOpen && (
              <div className="case-dropdown-menu" role="menu" aria-label="Saved cases list">
                {availableCases.length === 0 ? (
                  <p className="case-dropdown-empty">No saved cases yet.</p>
                ) : (
                  <ul className="case-dropdown-list">
                    {availableCases.map((savedCase) => (
                      <li key={savedCase}>
                        <button
                          type="button"
                          role="menuitem"
                          className={`case-dropdown-item ${savedCase === caseId ? 'case-dropdown-item-active' : ''}`}
                          onClick={() => selectCaseFromDropdown(savedCase)}
                        >
                          <span>{savedCase}</span>
                          {savedCase === caseId && <small>Active</small>}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
          <div className="case-context">
            <span className="case-context-label">CURRENT CASE</span>
            <strong>{caseDetails?.title || caseId || 'No case selected'}</strong>
            {caseDetails?.title && <small>{caseId}</small>}
            {caseDetails?.leadInvestigator && <small>Lead: {caseDetails.leadInvestigator}</small>}
            {caseDetails && <span className={`case-status-badge case-status-${caseDetails.status.toLowerCase().replaceAll(' ', '-')}`}>{caseDetails.status}</span>}
          </div>
          {casePopupOpen && caseId && (
            <div
              className="evidence-action-backdrop case-popup-backdrop"
              onClick={(event) => {
                if (event.target === event.currentTarget) setCasePopupOpen(false);
              }}
            >
              <div className="evidence-action-dialog case-popup-dialog" role="dialog" aria-modal="true" aria-labelledby="case-popup-title">
                <div className="case-popup-header">
                  <div>
                    <p className="eyebrow">CASE QUICK VIEW</p>
                    <h2 id="case-popup-title">{caseDetails?.title || caseId}</h2>
                  </div>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label="Close case popup"
                    onClick={() => setCasePopupOpen(false)}
                  >
                    <Icon name="close" size={16} />
                  </button>
                </div>
                <dl className="case-popup-meta">
                  <div>
                    <dt>Case ID</dt>
                    <dd>{caseId}</dd>
                  </div>
                  <div>
                    <dt>Status</dt>
                    <dd>{caseDetails?.status || 'Open'}</dd>
                  </div>
                  <div>
                    <dt>Lead Investigator</dt>
                    <dd>{caseDetails?.leadInvestigator || 'Not assigned'}</dd>
                  </div>
                  <div>
                    <dt>Evidence Files</dt>
                    <dd>{activeRecords.length} active{archivedRecords.length ? ` · ${archivedRecords.length} archived` : ''}</dd>
                  </div>
                </dl>
                {caseDetails?.description && (
                  <p className="case-popup-description">{caseDetails.description}</p>
                )}
                <div className="evidence-action-buttons">
                  <button
                    type="button"
                    className="button button-dark"
                    onClick={() => {
                      setCasePopupOpen(false);
                      navigateToWorkspace('cases');
                    }}
                  >
                    Case Management
                  </button>
                  <button
                    type="button"
                    className="button button-accent"
                    onClick={() => {
                      setCasePopupOpen(false);
                      navigateToWorkspace('evidence');
                    }}
                  >
                    Evidence Locker
                  </button>
                  <button
                    type="button"
                    className="button button-dark"
                    onClick={() => setCasePopupOpen(false)}
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
          {caseId && (
            <div className="team-case-registration">
              <button
                type="button"
                className="button button-dark"
                onClick={registerActiveCase}
                disabled={!supabase || !authSession?.user?.id || activeCaseRegistration?.status === 'registering'}
              >
                {activeCaseRegistration?.status === 'registering' ? 'Registering case…' : 'Register case for team access'}
              </button>
              <p
                className={`team-case-registration-message ${activeCaseRegistration?.status === 'registered' ? 'team-case-registration-success' : ''} ${activeCaseRegistration?.status === 'error' ? 'team-case-registration-error' : ''}`}
                role={activeCaseRegistration?.status === 'error' ? 'alert' : 'status'}
                aria-live="polite"
              >
                {activeCaseRegistration?.message
                  || (!supabaseConfigured
                    ? 'Supabase is not configured for this application.'
                    : !authSession?.user?.id
                      ? 'Sign in with Supabase to register this case.'
                      : 'Registration has not been checked for this account.')}
              </p>
            </div>
          )}
        </section>

        {activeWorkspace === 'cases' && (
          <section className="case-details-panel" aria-labelledby="case-details-title">
            <div className="case-details-heading">
              <div>
                <p className="eyebrow">INVESTIGATION RECORD</p>
                <h2 id="case-details-title">Case details</h2>
                <p>Update administrative case information. Evidence, hashes, encryption, and custody records are not changed.</p>
              </div>
              {caseId && <span className="case-details-id">CASE ID <strong>{caseId}</strong></span>}
            </div>
            {!caseId ? (
              <div className="case-details-empty">
                <p>Open a saved case or enter an existing case ID above to review its details.</p>
                <button type="button" className="button button-dark" onClick={() => caseInputRef.current?.focus()}>Choose a case</button>
              </div>
            ) : !caseDetails ? (
              <p role="status">Loading case details…</p>
            ) : (
              <form className="case-details-form" onSubmit={saveActiveCaseDetails}>
                <label htmlFor="case-title">Case Title
                  <input id="case-title" value={caseDetails.title} onChange={(event) => setCaseDetails({ ...caseDetails, title: event.target.value })} maxLength={200} placeholder="e.g. Unauthorized access investigation" />
                </label>
                <label htmlFor="case-lead-investigator">Lead Investigator
                  <input id="case-lead-investigator" value={caseDetails.leadInvestigator} onChange={(event) => setCaseDetails({ ...caseDetails, leadInvestigator: event.target.value })} maxLength={200} placeholder="Investigator name" />
                </label>
                <label htmlFor="case-status">Case Status
                  <select id="case-status" value={caseDetails.status} onChange={(event) => setCaseDetails({ ...caseDetails, status: event.target.value })}>
                    {['Open', 'In Progress', 'Under Review', 'Closed'].map((status) => <option key={status} value={status}>{status}</option>)}
                  </select>
                </label>
                <label htmlFor="case-description" className="case-description-field">Case Description
                  <textarea id="case-description" value={caseDetails.description} onChange={(event) => setCaseDetails({ ...caseDetails, description: event.target.value })} rows={5} maxLength={10000} placeholder="Record the investigation scope and context." />
                </label>
                <div className="case-date-grid" aria-label="Case timestamps">
                  <div><span>Date Created</span><strong>{formatDate(caseDetails.createdAt)}</strong></div>
                  <div><span>Date Last Updated</span><strong>{formatDate(caseDetails.updatedAt)}</strong></div>
                </div>
                <div className="case-details-actions">
                  <span>Case details are encrypted in this browser’s existing vault.</span>
                  <button type="submit" className="button button-accent" disabled={caseDetailsBusy || !db}>
                    {caseDetailsBusy ? 'Saving…' : 'Save case details'}
                  </button>
                </div>
              </form>
            )}
          </section>
        )}

        <section className="workspace-evidence-context" aria-label="Selected evidence">
          <strong className="workspace-active-case" title={caseDetails?.title || caseId}>{caseDetails?.title || caseId || 'No case selected'}</strong>
          <label htmlFor="workspace-evidence">Active evidence</label>
          <select
            id="workspace-evidence"
            aria-label="Active evidence"
            value={activeEvidenceSelection}
            onChange={(event) => setSelectedId(event.target.value || null)}
            disabled={!activeRecords.length}
          >
            {!activeRecords.length
              ? <option value="">No active evidence in this case</option>
              : !activeEvidenceSelection && <option value="">No active evidence selected</option>}
            {activeRecords.map((record) => <option key={record.id} value={record.id}>{record.name} · {record.id}</option>)}
          </select>
          <span>{selectedRecord?.sha256 ? `SHA-256 ${selectedRecord.sha256.slice(0, 12)}…` : 'Select a case and evidence record'}</span>
        </section>

        {activeWorkspace === 'overview' && (
          <div className="dashboard-brandline" aria-label="ClueBox Odyssey — Explore the Digital Unknown">
            <ClueBoxLogo size={38} />
            <span><strong>ClueBox Odyssey</strong><small>Explore the Digital Unknown.</small></span>
          </div>
        )}

        {activeWorkspace === 'overview' && <section className="summary-grid" aria-label="Investigation summary">
          <article className="summary-card">
            <span className="summary-card-icon"><Icon name="folder" size={18} /></span>
            <div><span>Evidence items</span><strong>{records.length}</strong><small>{caseId || 'Select a case to begin'}</small></div>
          </article>
          <article className="summary-card">
            <span className="summary-card-icon"><Icon name="shield" size={18} /></span>
            <div><span>Saved analyst reviews</span><strong>{savedAnalysisCount}</strong><small>Across active case evidence</small></div>
          </article>
          <article className="summary-card">
            <span className="summary-card-icon"><Icon name="clock" size={18} /></span>
            <div><span>Timeline events</span><strong>{timelineEvents.length}</strong><small>{timelineCaseId || 'No timeline case selected'}</small></div>
          </article>
          <article className="summary-card summary-card-status">
            <span className="summary-card-icon"><Icon name="sparkles" size={18} /></span>
            <div><span>Copilot service</span><strong>{copilotConfigured ? 'READY' : 'OFFLINE'}</strong><small>{copilotConfigured ? 'Secure provider available' : 'Provider setup required'}</small></div>
          </article>
        </section>}

        {activeWorkspace === 'overview' && <section className="module-directory" aria-labelledby="module-directory-title">
          <div className="module-directory-heading">
            <div>
              <p className="eyebrow">INVESTIGATION WORKSPACES</p>
              <h2 id="module-directory-title">Forensic modules</h2>
            </div>
            <p>Choose a workspace to continue reviewing this case.</p>
          </div>
          <div className="module-card-grid">
            {moduleCards.map((module) => (
              <button
                type="button"
                key={module.id}
                className="module-card"
                data-module={module.id}
                onClick={() => openModuleCard(module.id)}
                aria-label={module.title}
              >
                <span className="module-card-icon" aria-hidden="true"><Icon name={module.icon} size={22} /></span>
                <span className="module-card-copy">
                  <strong>{module.title}</strong>
                  <span>{module.description}</span>
                </span>
                <span className="module-card-arrow" aria-hidden="true"><Icon name="chevron" size={17} /></span>
              </button>
            ))}
          </div>
        </section>}

        {activeWorkspace === 'copilot' && (
          <section className="copilot-workspace-section" aria-labelledby="copilot-workspace-title">
            <header className="copilot-workspace-header">
              <div>
                <p className="eyebrow">AI FORENSIC OBSERVATORY · {caseId || 'NO CASE OPEN'}</p>
                <h2 id="copilot-workspace-title">AI Forensic Copilot Workspace</h2>
                <p>{copilotAvailability}</p>
              </div>
              <div className="copilot-workspace-tabs" role="tablist" aria-label="AI Copilot workspace sections">
                <button
                  type="button"
                  role="tab"
                  aria-selected={copilotWorkspaceTab === 'chat'}
                  className={`copilot-minitab-btn ${copilotWorkspaceTab === 'chat' ? 'copilot-minitab-btn-active' : ''}`}
                  onClick={() => setCopilotWorkspaceTab('chat')}
                >
                  Chat &amp; Analysis {copilotConversation.length > 0 ? `(${copilotConversation.length})` : ''}
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={copilotWorkspaceTab === 'toolkit'}
                  className={`copilot-minitab-btn ${copilotWorkspaceTab === 'toolkit' ? 'copilot-minitab-btn-active' : ''}`}
                  onClick={() => setCopilotWorkspaceTab('toolkit')}
                >
                  Toolkit Scan &amp; Facts {copilotFacts.length > 0 ? `(${copilotFacts.length})` : ''}
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={copilotWorkspaceTab === 'verify'}
                  className={`copilot-minitab-btn ${copilotWorkspaceTab === 'verify' ? 'copilot-minitab-btn-active' : ''}`}
                  onClick={() => setCopilotWorkspaceTab('verify')}
                >
                  Verify &amp; Log {savedCopilotFindings.length > 0 ? `(${savedCopilotFindings.length})` : ''}
                </button>
              </div>
            </header>
            <div className="copilot-workspace-body">
              {copilotWorkspaceTab === 'chat' && renderCopilotChatTab({ isMini: false, onSwitchTab: setCopilotWorkspaceTab })}
              {copilotWorkspaceTab === 'toolkit' && renderCopilotToolkitTab({ onSwitchTab: setCopilotWorkspaceTab })}
              {copilotWorkspaceTab === 'verify' && renderCopilotVerifyTab()}
            </div>
          </section>
        )}

        {copilotPanelOpen && appRootRef.current && createPortal(
          <section
            className={`copilot-section copilot-chat-panel ${copilotPanelExpanded ? 'copilot-chat-expanded' : ''} ${copilotPanelMinimized ? 'copilot-chat-minimized' : ''}`}
            id="copilot-chat-panel"
            role="dialog"
            aria-modal="false"
            aria-labelledby="copilot-title"
          >
            <header className="copilot-panel-header">
              <div className="copilot-panel-title">
                <span className="copilot-panel-mark" aria-hidden="true">AI</span>
                <div>
                  <h2 id="copilot-title">AI Forensic Copilot</h2>
                  <span>{caseId ? `Case ${caseId}` : 'No case selected'}</span>
                </div>
                <span className={`copilot-availability ${copilotConfigured ? 'copilot-available' : ''}`} role="status">{copilotConfigured ? 'Ready' : 'Offline'}</span>
              </div>
              <div className="copilot-panel-controls">
                <button
                  type="button"
                  className="copilot-panel-control copilot-panel-control-text"
                  title="Open full AI Copilot sidebar tab"
                  onClick={() => {
                    navigateToWorkspace('copilot');
                    setCopilotPanelOpen(false);
                  }}
                >Full tab</button>
                <button
                  type="button"
                  className="copilot-panel-control"
                  aria-label={copilotPanelMinimized ? 'Restore AI Copilot chat' : 'Minimize AI Copilot chat'}
                  title={copilotPanelMinimized ? 'Restore chat' : 'Minimize chat'}
                  onClick={() => setCopilotPanelMinimized((minimized) => !minimized)}
                >{copilotPanelMinimized ? '□' : '−'}</button>
                <button
                  type="button"
                  className="copilot-panel-control"
                  aria-label={copilotPanelExpanded ? 'Restore AI Copilot chat size' : 'Expand AI Copilot chat'}
                  aria-expanded={copilotPanelExpanded}
                  title={copilotPanelExpanded ? 'Restore chat size' : 'Expand chat'}
                  onClick={() => setCopilotPanelExpanded((expanded) => !expanded)}
                >{copilotPanelExpanded ? '↙' : '↗'}</button>
                <button type="button" className="copilot-panel-control" aria-label="Close AI Copilot chat" title="Close chat" onClick={closeCopilotPanel}>
                  <Icon name="close" size={16} />
                </button>
              </div>
            </header>

            {!copilotPanelMinimized && (
              <>
                <nav className="copilot-minitab-nav" role="tablist" aria-label="Copilot minitab sections">
                  <button
                    type="button"
                    role="tab"
                    aria-selected={copilotMiniTab === 'chat'}
                    className={`copilot-minitab-btn ${copilotMiniTab === 'chat' ? 'copilot-minitab-btn-active' : ''}`}
                    onClick={() => setCopilotMiniTab('chat')}
                  >
                    Chat {copilotConversation.length > 0 ? `(${copilotConversation.length})` : ''}
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={copilotMiniTab === 'toolkit'}
                    className={`copilot-minitab-btn ${copilotMiniTab === 'toolkit' ? 'copilot-minitab-btn-active' : ''}`}
                    onClick={() => setCopilotMiniTab('toolkit')}
                  >
                    Toolkit &amp; Facts {copilotFacts.length > 0 ? `(${copilotFacts.length})` : ''}
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={copilotMiniTab === 'verify'}
                    className={`copilot-minitab-btn ${copilotMiniTab === 'verify' ? 'copilot-minitab-btn-active' : ''}`}
                    onClick={() => setCopilotMiniTab('verify')}
                  >
                    Verify &amp; Log {savedCopilotFindings.length > 0 ? `(${savedCopilotFindings.length})` : ''}
                  </button>
                </nav>
                <div className="copilot-chat-body">
                  {copilotMiniTab === 'chat' && renderCopilotChatTab({ isMini: true, onSwitchTab: setCopilotMiniTab })}
                  {copilotMiniTab === 'toolkit' && renderCopilotToolkitTab({ onSwitchTab: setCopilotMiniTab })}
                  {copilotMiniTab === 'verify' && renderCopilotVerifyTab()}
                </div>
              </>
            )}
          </section>,
          appRootRef.current,
        )}

        {activeWorkspace === 'timeline' && <section className="timeline-section" aria-labelledby="timeline-title">
          <div className="timeline-heading">
            <div>
              <p className="eyebrow">CHRONOLOGICAL EVIDENCE REVIEW</p>
              <h2 id="timeline-title">Investigation Timeline</h2>
              <p>Events are derived from saved evidence metadata and analyst reports. Source values are retained; timezone-ambiguous values are not converted to UTC.</p>
            </div>
            <label>Investigation case
              <select aria-label="Timeline case" value={timelineCaseId} onChange={(event) => {
                setTimelineCaseId(event.target.value);
                setTimelineFilters({ evidenceId: '', module: '', startDate: '', endDate: '', validationStatus: '', timestampStatus: '' });
              }}>
                <option value="">Select a saved case</option>
                {[...new Set([...cases, ...(caseId ? [caseId] : [])])].sort().map((savedCase) => <option key={savedCase} value={savedCase}>{savedCase}</option>)}
              </select>
            </label>
          </div>
          {timelineError && <p className="timeline-error" role="alert">{timelineError}</p>}
          {timelineCaseId && (
            <>
              <div className="timeline-filters" aria-label="Timeline filters">
                <label>Evidence
                  <select value={timelineFilters.evidenceId} onChange={(event) => setTimelineFilters((current) => ({ ...current, evidenceId: event.target.value }))}>
                    <option value="">All evidence</option>
                    {timelineRecords.map((record) => <option key={record.id} value={record.id}>{record.name} ({record.id})</option>)}
                  </select>
                </label>
                <label>Source module
                  <select value={timelineFilters.module} onChange={(event) => setTimelineFilters((current) => ({ ...current, module: event.target.value }))}>
                    <option value="">All modules</option>
                    {timelineModules.map((module) => <option key={module} value={module}>{module}</option>)}
                  </select>
                </label>
                <label>From date (UTC)
                  <input type="date" value={timelineFilters.startDate} onChange={(event) => setTimelineFilters((current) => ({ ...current, startDate: event.target.value }))} />
                </label>
                <label>To date (UTC)
                  <input type="date" value={timelineFilters.endDate} onChange={(event) => setTimelineFilters((current) => ({ ...current, endDate: event.target.value }))} />
                </label>
                <label>Validation
                  <select value={timelineFilters.validationStatus} onChange={(event) => setTimelineFilters((current) => ({ ...current, validationStatus: event.target.value }))}>
                    <option value="">All statuses</option>
                    <option>VERIFIED</option><option>MISMATCH</option><option>NEEDS REVIEW</option>
                  </select>
                </label>
                <label>Timestamp certainty
                  <select value={timelineFilters.timestampStatus} onChange={(event) => setTimelineFilters((current) => ({ ...current, timestampStatus: event.target.value }))}>
                    <option value="">All timestamps</option>
                    <option value="known">Normalized UTC</option><option value="unknown">Unknown / ambiguous</option>
                  </select>
                </label>
                <button type="button" className="text-button" onClick={() => setTimelineFilters({ evidenceId: '', module: '', startDate: '', endDate: '', validationStatus: '', timestampStatus: '' })}>Clear filters</button>
              </div>
              <div className="timeline-actions">
                <div className="timeline-view-tabs" role="tablist" aria-label="Timeline view mode">
                  <button
                    type="button"
                    role="tab"
                    aria-selected={timelineViewMode === 'standard'}
                    className={`button ${timelineViewMode === 'standard' ? 'button-accent' : 'button-dark'}`}
                    onClick={() => setTimelineViewMode('standard')}
                  >
                    Standard Timeline ({filteredTimelineEvents.length})
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={timelineViewMode === 'ai'}
                    className={`button ${timelineViewMode === 'ai' ? 'button-accent' : 'button-dark'}`}
                    onClick={() => setTimelineViewMode('ai')}
                  >
                    AI-Analyzed Timeline
                  </button>
                </div>
                <div>
                  <button
                    type="button"
                    className="button button-accent"
                    onClick={() => {
                      setTimelineViewMode('ai');
                      generateAiTimelineAnalysis();
                    }}
                    disabled={aiTimelineBusy || !copilotAccessReady || !timelineRecords.length}
                  >
                    {aiTimelineBusy ? 'Analyzing timeline…' : 'Generate AI Timeline Analysis'}
                  </button>
                  <button type="button" className="button button-dark" onClick={() => downloadTimeline('json')} disabled={!filteredTimelineEvents.length}>Export timeline JSON</button>
                  <button type="button" className="button button-dark" onClick={() => downloadTimeline('csv')} disabled={!filteredTimelineEvents.length}>Export timeline CSV</button>
                </div>
              </div>
              {timelineViewMode === 'ai' ? (
                <div className="ai-timeline-panel" aria-label="AI-analyzed timeline">
                  {aiTimelineError && <p className="timeline-error" role="alert">{aiTimelineError}</p>}
                  {!aiTimelineAnalysis || aiTimelineAnalysis.caseId !== timelineCaseId ? (
                    <div className="ai-timeline-empty">
                      <h3>AI-Analyzed Timeline View</h3>
                      <p>Generate an AI-analyzed chronological view across all logs, custody records, metadata, and toolkit outputs for {timelineCaseId}. All AI timeline findings are documented in the case vault and require custodian/investigator verification.</p>
                      <button
                        type="button"
                        className="button button-accent"
                        onClick={generateAiTimelineAnalysis}
                        disabled={aiTimelineBusy || !copilotAccessReady || !timelineRecords.length}
                      >
                        {aiTimelineBusy ? 'Generating AI timeline analysis…' : 'Generate AI-Analyzed Timeline'}
                      </button>
                    </div>
                  ) : (
                    <>
                      <div className="ai-timeline-banner">
                        <div>
                          <p className="eyebrow">AI-ANALYZED TIMELINE · {aiTimelineAnalysis.caseId}</p>
                          <h3>Generated {formatDate(aiTimelineAnalysis.generatedAt)} from {aiTimelineAnalysis.sourceEventCount} timeline events &amp; {aiTimelineAnalysis.facts.length} verified facts</h3>
                        </div>
                        <div className="ai-timeline-banner-actions">
                          <span className={`validation-status validation-${(aiTimelineSavedFinding?.status || 'NEEDS REVIEW').toLowerCase().replaceAll(' ', '-')}`}>
                            {aiTimelineSavedFinding?.status || 'NEEDS REVIEW'}
                          </span>
                          <button type="button" className="button button-dark" onClick={downloadAiTimelineReport}>
                            Export AI Timeline Report (JSON)
                          </button>
                        </div>
                      </div>

                      {aiTimelineAnalysis.response.summary && (
                        <p className="copilot-executive-summary">{aiTimelineAnalysis.response.summary}</p>
                      )}

                      {aiTimelineAnalysis.response.analyzedTimeline?.length > 0 && (
                        <div className="timeline-event-list">
                          <h3>AI-Correlated Chronological Events ({aiTimelineAnalysis.response.analyzedTimeline.length})</h3>
                          {aiTimelineAnalysis.response.analyzedTimeline.map((item, idx) => (
                            <article className="timeline-event ai-timeline-event" key={`ai-tl-${idx}`}>
                              <div className="ai-timeline-event-time">
                                <strong>{item.timestamp}</strong>
                                <span className={`ai-sig-badge ai-sig-${item.significance.toLowerCase()}`}>{item.significance} PRIORITY</span>
                              </div>
                              <div>
                                <strong>{item.eventSummary}</strong>
                                <span>{item.analysis}</span>
                                <code>Citations: {item.evidenceRefs.join(', ')}</code>
                              </div>
                              <span className="timeline-status">{aiTimelineSavedFinding?.status || 'NEEDS REVIEW'}</span>
                            </article>
                          ))}
                        </div>
                      )}

                      <div className="ai-timeline-grid">
                        {[
                          ['Objective Conclusions', aiTimelineAnalysis.response.objectiveConclusions || []],
                          ['Cross-Artifact Connections', aiTimelineAnalysis.response.connections || []],
                          ['Gaps & Timestamp Anomalies', aiTimelineAnalysis.response.gapsAndAnomalies || []],
                          ['Viable Next Steps', aiTimelineAnalysis.response.recommendations || []],
                        ].map(([heading, items]) => (
                          <section className="ai-timeline-card" key={heading}>
                            <h4>{heading}</h4>
                            {items.length ? items.map((claim, idx) => (
                              <article className="copilot-claim" key={`${heading}-${idx}`}>
                                <p>{claim.text}</p>
                                <small>Evidence references: {claim.evidenceRefs.join(', ')}</small>
                              </article>
                            )) : <p className="copilot-empty">No items identified.</p>}
                          </section>
                        ))}
                      </div>

                      {aiTimelineAnalysis.response.workflow?.length > 0 && (
                        <section className="ai-timeline-card">
                          <h4>Recommended Verification &amp; Investigation Workflow</h4>
                          <ol className="copilot-workflow-list">
                            {aiTimelineAnalysis.response.workflow.map((step) => (
                              <li className="copilot-workflow-step" key={`tl-wf-${step.step}`}>
                                <div className="copilot-workflow-head">
                                  <strong>Step {step.step}: {step.title}</strong>
                                  <button type="button" className="copilot-module-jump" onClick={() => jumpToWorkflowModule(step.module)}>
                                    {step.module} →
                                  </button>
                                </div>
                                <p>{step.action}</p>
                                <small>Evidence references: {step.evidenceRefs.join(', ')}</small>
                              </li>
                            ))}
                          </ol>
                        </section>
                      )}

                      <section className="ai-timeline-verify-card" aria-label="Custodian and investigator timeline verification">
                        <div className="copilot-result-heading">
                          <h4>Custodian / Investigator Verification Gate</h4>
                          <span>{aiTimelineSavedFinding?.status || 'NEEDS REVIEW'}</span>
                        </div>
                        <p>Review the AI-analyzed timeline against the raw Standard Timeline and source evidence. Record your sign-off below to verify and log a cryptographic Chain of Custody event.</p>
                        <form className="copilot-review-form" onSubmit={verifyAiTimelineAnalysis}>
                          <label>Custodian / Investigator Name
                            <input
                              required
                              value={aiTimelineReview.analyst}
                              placeholder="Enter custodian or investigator name"
                              onChange={(event) => setAiTimelineReview((curr) => ({ ...curr, analyst: event.target.value }))}
                            />
                          </label>
                          <label>Verification Status
                            <select
                              value={aiTimelineReview.status}
                              onChange={(event) => setAiTimelineReview((curr) => ({ ...curr, status: event.target.value }))}
                            >
                              <option>VERIFIED</option>
                              <option>MISMATCH</option>
                              <option>NEEDS REVIEW</option>
                            </select>
                          </label>
                          <label>Independent Verification Method / Tool
                            <input
                              required
                              value={aiTimelineReview.independentMethod}
                              placeholder="e.g. Cross-checked UTC timestamps, custody hashes, and raw artifacts"
                              onChange={(event) => setAiTimelineReview((curr) => ({ ...curr, independentMethod: event.target.value }))}
                            />
                          </label>
                          <label>Verification Notes
                            <textarea
                              required
                              rows="2"
                              value={aiTimelineReview.notes}
                              placeholder="Record confirmation, corrections, or timestamp caveats"
                              onChange={(event) => setAiTimelineReview((curr) => ({ ...curr, notes: event.target.value }))}
                            />
                          </label>
                          <label className="copilot-approval">
                            <input
                              type="checkbox"
                              checked={aiTimelineReview.attested}
                              onChange={(event) => setAiTimelineReview((curr) => ({ ...curr, attested: event.target.checked }))}
                            />
                            I attest as custodian/investigator that I independently verified this AI-analyzed timeline against the case records and logs.
                          </label>
                          <button
                            type="submit"
                            className="button button-accent"
                            disabled={copilotBusy || !aiTimelineReview.attested || !aiTimelineReview.analyst.trim()}
                          >
                            Record Custodian / Investigator Verification
                          </button>
                        </form>
                        {aiTimelineSavedFinding?.validationHistory?.length > 0 && (
                          <div className="ai-timeline-history">
                            {aiTimelineSavedFinding.validationHistory.map((entry, idx) => (
                              <p className="copilot-validation-history" key={`tl-val-${idx}`}>
                                {entry.status} by {entry.analyst} ({entry.investigatorId}) on {formatDate(entry.reviewedAt)} · {entry.independentMethod} — {entry.notes}
                              </p>
                            ))}
                          </div>
                        )}
                      </section>
                    </>
                  )}
                </div>
              ) : (
                <>
              {filteredTimelineEvents.filter((event) => event.timestamp).length > 0 ? (
                <div className="timeline-event-list">
                  <h3>Chronological events (UTC)</h3>
                  {filteredTimelineEvents.filter((event) => event.timestamp).map((event) => (
                    <article className={`timeline-event timeline-event-${event.validationStatus.toLowerCase().replaceAll(' ', '-')}`} key={event.id}>
                      <time dateTime={event.timestamp}>{formatDate(event.timestamp)} <small>{event.timeZone}</small></time>
                      <div>
                        <strong>{event.description}</strong>
                        <span>{event.sourceModule} · {event.caseId} · {event.evidenceId} · {event.filename}</span>
                        <code>{event.artifactReference}</code>
                        <small>Original timestamp: {formatTimestampSource(event.originalTimestamp)} · {event.timestampStatus}</small>
                      </div>
                      <span className="timeline-status">{event.validationStatus}{event.classification === 'VERIFIED FINDING' ? ' · VERIFIED FINDING' : ' · UNVERIFIED'}</span>
                    </article>
                  ))}
                </div>
              ) : <p className="timeline-empty">No chronologically normalized events match these filters.</p>}
              {filteredTimelineEvents.filter((event) => !event.timestamp).length > 0 && (
                <div className="timeline-event-list timeline-unknown-events">
                  <h3>Unknown or ambiguous timestamps ({filteredTimelineEvents.filter((event) => !event.timestamp).length})</h3>
                  <p>These events are intentionally not positioned on the UTC chronology because their source timestamp lacks a reliable time or timezone.</p>
                  {filteredTimelineEvents.filter((event) => !event.timestamp).map((event) => (
                    <article className={`timeline-event timeline-event-${event.validationStatus.toLowerCase().replaceAll(' ', '-')}`} key={event.id}>
                      <div className="timeline-time-unknown">
                        <strong>{event.timestampStatus}</strong>
                        <small>{event.timeZone}</small>
                        <small>Original value: {formatTimestampSource(event.originalTimestamp)}</small>
                      </div>
                      <div>
                        <strong>{event.description}</strong>
                        <span>{event.sourceModule} · {event.caseId} · {event.evidenceId} · {event.filename}</span>
                        <code>{event.artifactReference}</code>
                      </div>
                      <span className="timeline-status">{event.validationStatus}{event.classification === 'VERIFIED FINDING' ? ' · VERIFIED FINDING' : ' · UNVERIFIED'}</span>
                    </article>
                  ))}
                </div>
              )}
                </>
              )}
            </>
          )}
        </section>}

        {activeWorkspace === 'reports' && <section className="investigation-report-section" aria-labelledby="report-title">
          <div className="timeline-heading">
            <div>
              <p className="eyebrow">CASE DOCUMENTATION</p>
              <h2 id="report-title">Final Investigation Report</h2>
              <p>Generates a separate downloadable JSON report after rechecking evidence hashes and custody chains. No vault records are modified.</p>
            </div>
            <ReportExportActions
              onDownload={downloadInvestigationReport}
              disabled={!timelineCaseId || !timelineRecords.length}
              busy={reportBusy}
            />
          </div>
          <div className="report-editor">
            <label>Investigation summary
              <textarea rows="3" value={reportSummary} onChange={(event) => setReportSummary(event.target.value)} placeholder="Enter a concise case summary. This text is investigator supplied." />
            </label>
            <label>Investigator conclusions
              <textarea rows="3" value={reportConclusions} onChange={(event) => setReportConclusions(event.target.value)} placeholder="Record investigator conclusions and limitations. AI content is not verified by default." />
            </label>
          </div>
          {reportError && <p className="timeline-error" role="alert">{reportError}</p>}
          {reportNotice && <p className="report-notice" role="status">{reportNotice}</p>}
          <SavedAnalysisReports records={records} caseId={caseId} />
        </section>}

        {(error || notice) && (
          <div className={`feedback ${error ? 'feedback-error' : 'feedback-success'}`} role={error ? 'alert' : 'status'}>
            <span>{error || notice}</span>
            <button type="button" className="icon-button feedback-dismiss" aria-label="Dismiss message" onClick={() => { setError(''); setNotice(''); }}><Icon name="close" size={16} /></button>
          </div>
        )}
        {navigationWarning && (
          <div className="feedback feedback-error" role="status">
            <span>{navigationWarning}</span>
          </div>
        )}

        {evidenceWorkspaceVisible && <div className={`dashboard-grid dashboard-grid-${activeWorkspace}`}>
          <section className="evidence-column" aria-label="Case evidence" hidden={activeWorkspace !== 'evidence'}>
            <div className="section-header">
              <div>
                <h2>Evidence files <span className="count-badge">{records.length}</span></h2>
                <p>{caseId ? `Items filed under ${caseId}` : 'Open a case to view or add evidence'}</p>
              </div>
              {caseId && (
                <button type="button" className="button button-accent" disabled={busy || !db} onClick={() => fileInput.current?.click()}>
                  <Icon name="plus" size={17} /> Add evidence
                </button>
              )}
              <input ref={fileInput} className="visually-hidden" type="file" multiple disabled={!caseId || busy} onChange={(event) => handleFiles(event.target.files)} aria-label="Choose evidence files" />
            </div>

            {caseId && (
              <div
                className={`drop-zone ${dragging ? 'drop-zone-active' : ''} ${busy ? 'drop-zone-busy' : ''}`}
                onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => { event.preventDefault(); setDragging(false); handleFiles(event.dataTransfer.files); }}
              >
                <span className="drop-icon"><Icon name={busy ? 'lock' : 'upload'} size={19} /></span>
                <span className="drop-copy"><strong>{busy ? 'Encrypting and cataloging…' : 'Drop evidence files here'}</strong><span>Files are encrypted in this browser before being stored.</span></span>
                <button type="button" className="text-button" disabled={busy || !db} onClick={() => fileInput.current?.click()}>{busy ? 'Please wait' : 'Browse files'}</button>
              </div>
            )}

            <div className="list-toolbar">
              <div className="evidence-list-views" aria-label="Evidence record view">
                <button
                  type="button"
                  aria-pressed={evidenceListView === 'active'}
                  onClick={() => {
                    setEvidenceListView('active');
                    if (selectedRecord?.archivedAt) setSelectedId(activeRecords[0]?.id ?? null);
                  }}
                >
                  Active evidence ({activeRecords.length})
                </button>
                {canManageCaseEvidence && (
                  <button
                    type="button"
                    aria-pressed={evidenceListView === 'archived'}
                    onClick={openArchivedEvidence}
                  >
                    Archived evidence ({archivedRecords.length})
                  </button>
                )}
              </div>
              <label className="search-box">
                <Icon name="search" size={16} />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search files or hash" aria-label="Search evidence" />
              </label>
            </div>

            {visibleEvidenceRecords.length > 0 ? (
              filteredRecords.length > 0 ? (
                <div className="evidence-list">
                  <div className="list-head"><span>FILE</span><span>ADDED</span><span>SHA-256</span><span>STATUS</span></div>
                  {filteredRecords.map((record) => (
                    <button type="button" className={`evidence-row ${selectedId === record.id ? 'evidence-row-selected' : ''}`} key={record.id} onClick={() => setSelectedId(record.id)}>
                      <span className="file-cell"><span className="file-icon"><Icon name="file" size={17} /></span><span className="file-name-wrap"><strong>{record.name}</strong><small>{formatBytes(record.size)} <span className="file-type">{record.type || 'Unknown type'}</span></small></span></span>
                      <span className="date-cell">{formatDate(record.createdAt)}</span>
                      <span className="hash-cell">{record.sha256.slice(0, 12)}…</span>
                      <span className="status-cell"><span className="status-mark"><Icon name="check" size={12} /></span> {record.archivedAt ? 'Archived' : 'Secured'}</span>
                    </button>
                  ))}
                </div>
              ) : <div className="empty-search">No evidence matches “{query}”.</div>
            ) : records.length > 0 ? (
              <div className="detail-placeholder">
                <h3>No {evidenceListView} evidence</h3>
                <p>{evidenceListView === 'archived' ? 'Archived evidence will appear here for authorized case investigators.' : 'All evidence in this case is archived.'}</p>
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-art"><span><Icon name="file" size={23} /></span><i /><i /></div>
                <h3>{caseId ? 'This case is ready for evidence' : 'Start with a case ID'}</h3>
                <p>{caseId ? 'Add files to create encrypted records with a SHA-256 fingerprint and custody event.' : 'Enter a case ID above to open an existing case or begin a new one.'}</p>
                {caseId && <button type="button" className="button button-accent" disabled={busy || !db} onClick={() => fileInput.current?.click()}><Icon name="upload" size={17} /> Select evidence</button>}
              </div>
            )}
          </section>

          <section className="detail-column" aria-label={analysisWorkspace ? `${workspaces[activeWorkspace][0]} workspace` : 'Evidence details'} hidden={activeWorkspace !== 'evidence' && !analysisWorkspace}>
            {selectedRecord ? (
              <>
                {selectedRecord.archivedAt && (
                  <div className="archived-evidence-notice" role="status">
                    <strong>Archived evidence — historical review only</strong>
                    <span>Archived {formatDate(selectedRecord.archivedAt)} by {selectedRecord.archive?.analyst || 'unknown analyst'}.</span>
                  </div>
                )}
                <div className="detail-heading" hidden={analysisWorkspace && activeWorkspace !== 'exif'}>
                  <div className="detail-title-wrap"><span className="detail-file-icon"><Icon name="file" size={19} /></span><div><p className="eyebrow">EVIDENCE RECORD</p><h2 title={selectedRecord.name}>{selectedRecord.name}</h2></div></div>
                  <button type="button" className="icon-button download-button" onClick={handleDownload} aria-label="Decrypt and download evidence" title="Decrypt and download"><Icon name="download" size={18} /></button>
                </div>

                <div className="integrity-banner" hidden={analysisWorkspace && activeWorkspace !== 'exif'}>
                  <span className="integrity-icon"><Icon name={custodyChainValid ? 'shield' : 'close'} size={16} /></span>
                  <span><strong>{custodyChainValid ? 'Custody chain verified' : 'Custody chain check failed'}</strong><small>{custodyChainValid ? 'Event links match the stored record' : 'One or more event links do not match'}</small></span>
                </div>

                <div className="metadata-section" hidden={analysisWorkspace && activeWorkspace !== 'exif'}>
                  <div className="detail-section-title"><h3>File metadata</h3><span>EXTRACTED</span></div>
                  <dl className="metadata-list">
                    <div><dt>File type</dt><dd>{selectedRecord.type || 'Unknown'}</dd></div>
                    {selectedRecord.pdfVersion && <div><dt>PDF version</dt><dd>{selectedRecord.pdfVersion}</dd></div>}
                    {selectedRecord.dimensions && <div><dt>Dimensions</dt><dd>{selectedRecord.dimensions}</dd></div>}
                    {selectedRecord.duration && <div><dt>Duration</dt><dd>{selectedRecord.duration}</dd></div>}
                    {selectedRecord.exif && Object.entries(selectedRecord.exif).map(([field, value]) => (
                      <div key={field}>
                        <dt>{exifLabels[field] || field}</dt>
                        <dd>{field.startsWith('gps') && typeof value === 'number' ? `${value.toFixed(6)}${field === 'gpsAltitudeMeters' ? ' m' : '°'}` : value}</dd>
                      </div>
                    ))}
                    <div><dt>File size</dt><dd>{formatBytes(selectedRecord.size)}</dd></div>
                    <div><dt>Modified</dt><dd>{formatDate(selectedRecord.lastModified)}</dd></div>
                  </dl>
                  <EvidenceIntegrity database={db} record={selectedRecord} />
                  {selectedRecord.exif && <p className="exif-disclaimer">EXIF values are embedded in the file and may be absent, inaccurate, or altered.</p>}
                </div>

                <section className="evidence-management-section" aria-label="Evidence archive and replacement" hidden={analysisWorkspace}>
                  <div className="detail-section-title"><h3>Evidence status</h3><span>{selectedRecord.archivedAt ? 'ARCHIVED' : 'ACTIVE'}</span></div>
                  {selectedRecord.archivedAt ? (
                    <>
                      <p className="evidence-management-copy">
                        {selectedRecord.archive?.action === 'replaced' ? 'Replaced' : 'Removed from the active case'} by {selectedRecord.archive?.analyst || 'unknown analyst'}.
                        {selectedRecord.archive?.reason ? ` Reason: ${selectedRecord.archive.reason}` : ''}
                      </p>
                      {(selectedRecord.replacementEvidenceId || selectedRecord.replacement?.originalEvidenceId) && (
                        <button
                          type="button"
                          className="text-button evidence-related-link"
                          onClick={() => setSelectedId(
                            selectedRecord.replacementEvidenceId || selectedRecord.replacement?.originalEvidenceId,
                          )}
                        >
                          {selectedRecord.replacementEvidenceId
                            ? `Review replacement evidence ${selectedRecord.replacementEvidenceId}`
                            : `Review original evidence ${selectedRecord.replacement.originalEvidenceId}`}
                        </button>
                      )}
                    </>
                  ) : (
                    <>
                      {selectedRecord.replacement?.originalEvidenceId && (
                        <button
                          type="button"
                          className="text-button evidence-related-link"
                          onClick={() => setSelectedId(selectedRecord.replacement.originalEvidenceId)}
                        >
                          Replacement for evidence {selectedRecord.replacement.originalEvidenceId}
                        </button>
                      )}
                      {canManageCaseEvidence ? (
                        <div className="evidence-management-actions">
                          <button type="button" className="button button-dark" onClick={() => openEvidenceAction('archive')} disabled={busy}>
                            Remove from Case
                          </button>
                          <button type="button" className="button button-accent" onClick={() => openEvidenceAction('replace')} disabled={busy}>
                            Replace Evidence
                          </button>
                        </div>
                      ) : (
                        <p className="evidence-management-copy" role="status">
                          Sign in and register this case with an Admin or Investigator role to archive or replace evidence.
                        </p>
                      )}
                    </>
                  )}
                  {evidenceAction && (
                    <div className="evidence-action-backdrop">
                      <form
                        className="evidence-action-dialog"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="evidence-action-title"
                        onSubmit={confirmEvidenceAction}
                      >
                        <h2 id="evidence-action-title">
                          {evidenceAction === 'replace' ? 'Confirm Evidence Replacement' : 'Confirm Remove from Case'}
                        </h2>
                        <p>
                          {evidenceAction === 'replace'
                            ? 'The replacement will be stored as a new encrypted evidence record. The original will be archived with its hash, file, reports, and custody history intact.'
                            : 'This archives the record from the active case view. Its encrypted file, SHA-256, reports, and custody history will be retained.'}
                        </p>
                        <label htmlFor="evidence-action-analyst">Analyst</label>
                        <input
                          id="evidence-action-analyst"
                          value={evidenceActionAnalyst}
                          onChange={(event) => setEvidenceActionAnalyst(event.target.value)}
                          maxLength={200}
                          required
                        />
                        {supabaseConfigured && authSession?.user?.email && (
                          <small>Signed in as {authSession.user.email}; user ID will be recorded in the audit event.</small>
                        )}
                        {evidenceAction === 'replace' && (
                          <>
                            <label htmlFor="replacement-evidence-file">Replacement evidence file</label>
                            <input
                              id="replacement-evidence-file"
                              type="file"
                              required
                              onChange={(event) => setReplacementFile(event.target.files?.[0] || null)}
                            />
                          </>
                        )}
                        <label htmlFor="evidence-action-reason">Reason (required)</label>
                        <textarea
                          id="evidence-action-reason"
                          value={evidenceActionReason}
                          onChange={(event) => setEvidenceActionReason(event.target.value)}
                          maxLength={5000}
                          rows={3}
                          required
                        />
                        <div className="evidence-action-buttons">
                          <button type="button" className="button button-dark" onClick={closeEvidenceAction} disabled={busy}>Cancel</button>
                          <button
                            type="submit"
                            className="button button-accent"
                            disabled={busy || !evidenceActionAnalyst.trim() || !evidenceActionReason.trim()
                              || (evidenceAction === 'replace' && !replacementFile)}
                          >
                            {busy ? 'Recording…' : `Confirm ${evidenceAction === 'replace' ? 'Replace Evidence' : 'Remove from Case'}`}
                          </button>
                        </div>
                      </form>
                    </div>
                  )}
                </section>

                <section className="exif-validation-section" aria-label="EXIF analysis and manual validation" hidden={activeWorkspace !== 'exif'}>
                  <div className="detail-section-title">
                    <h3>Manual EXIF validation</h3>
                    {selectedRecord.exifValidation && (
                      <span className={`validation-status validation-${selectedRecord.exifValidation.status.toLowerCase().replaceAll(' ', '-')}`}>
                        {selectedRecord.exifValidation.status}
                      </span>
                    )}
                  </div>
                  {selectedRecord.exifValidation && (
                    <p className="validation-summary">
                      Last reviewed by {selectedRecord.exifValidation.analyst} on {formatDate(selectedRecord.exifValidation.reviewedAt)}.
                    </p>
                  )}
                  <form className="exif-validation-form" onSubmit={saveManualExifValidation}>
                    <label htmlFor="exif-validation-status">Validation status</label>
                    <select id="exif-validation-status" value={exifValidationStatus} onChange={(event) => setExifValidationStatus(event.target.value)}>
                      <option>VERIFIED</option>
                      <option>MISMATCH</option>
                      <option>NEEDS REVIEW</option>
                    </select>
                    <label htmlFor="exif-analyst">Analyst</label>
                    <input id="exif-analyst" value={exifAnalyst} onChange={(event) => setExifAnalyst(event.target.value)} required />
                    <label htmlFor="exif-notes">Analyst notes</label>
                    <textarea id="exif-notes" value={exifNotes} onChange={(event) => setExifNotes(event.target.value)} rows="3" />
                    <label htmlFor="exif-artifact-references">Artifact references</label>
                    <textarea id="exif-artifact-references" value={exifArtifactReferences} onChange={(event) => setExifArtifactReferences(event.target.value)} rows="2" placeholder="One reference per line" />
                    <button type="submit" className="button button-dark" disabled={busy || !exifAnalyst.trim() || Boolean(selectedRecord.archivedAt)}>Save validation</button>
                  </form>
                  {selectedRecord.exifValidation?.artifactReferences.length > 0 && (
                    <ul className="artifact-reference-list" aria-label="Saved artifact references">
                      {selectedRecord.exifValidation.artifactReferences.map((reference, index) => <li key={`${reference}-${index}`}>{reference}</li>)}
                    </ul>
                  )}
                </section>

                <section className="registry-analysis-section" aria-label="Windows Registry analysis" hidden={activeWorkspace !== 'registry'}>
                  <div className="detail-section-title">
                    <h3>Windows Registry analysis</h3>
                    <span>OFFLINE HIVE</span>
                  </div>
                  <p className="registry-analysis-copy">Analyze a REGF hive locally. Analysis reads a verified copy and does not change the original evidence or SHA-256.</p>
                  <button type="button" className="button button-dark" onClick={analyzeRegistryHive} disabled={busy || Boolean(selectedRecord.archivedAt)}>
                    {busy ? 'Analyzing…' : 'Analyze selected evidence'}
                  </button>
                  {registryReport && (
                    <>
                      <RegistryAnalysisResults report={registryReport} evidence={selectedRecord} />
                      <form className="exif-validation-form" onSubmit={saveRegistryReport}>
                        <label htmlFor="registry-validation-status">Analyst validation</label>
                        <select id="registry-validation-status" value={registryValidationStatus} onChange={(event) => setRegistryValidationStatus(event.target.value)}>
                          <option>VERIFIED</option>
                          <option>MISMATCH</option>
                          <option>NEEDS REVIEW</option>
                        </select>
                        <label htmlFor="registry-analyst">Analyst</label>
                        <input id="registry-analyst" value={registryAnalyst} onChange={(event) => setRegistryAnalyst(event.target.value)} required />
                        <label htmlFor="registry-notes">Analyst notes</label>
                        <textarea id="registry-notes" value={registryNotes} onChange={(event) => setRegistryNotes(event.target.value)} rows="3" />
                        <label htmlFor="registry-artifact-references">Artifact references</label>
                        <textarea id="registry-artifact-references" value={registryArtifactReferences} onChange={(event) => setRegistryArtifactReferences(event.target.value)} rows="2" placeholder="One reference per line" />
                        <button type="submit" className="button button-dark" disabled={busy || !registryAnalyst.trim() || Boolean(selectedRecord.archivedAt)}>Save analysis report</button>
                      </form>
                    </>
                  )}
                  {selectedRecord.registryAnalysis && (
                    <div className="registry-saved-report">
                      <strong>Saved validation: {selectedRecord.registryAnalysis.status}</strong>
                      <span>Analyst: {selectedRecord.registryAnalysis.analyst}</span>
                      <button type="button" className="text-button" onClick={downloadRegistryReport}>Download analysis and custody report</button>
                    </div>
                  )}
                </section>

                <section className="registry-analysis-section" aria-label="PCAP network analysis" hidden={activeWorkspace !== 'pcap'}>
                  <div className="detail-section-title">
                    <h3>PCAP network analysis</h3>
                    <span>LOCAL ANALYSIS</span>
                  </div>
                  <p className="registry-analysis-copy">Analyze classic PCAP or PCAPNG locally from a hash-verified copy. Original evidence bytes and SHA-256 are preserved.</p>
                  <button type="button" className="button button-dark" onClick={analyzePcap} disabled={busy || Boolean(selectedRecord.archivedAt)}>
                    {busy ? 'Analyzing…' : 'Analyze selected capture'}
                  </button>
                  {pcapReport && (
                    <>
                      <div className="registry-analysis-summary">
                        <strong>{pcapReport.format}</strong>
                        <span>{pcapReport.packetCount.toLocaleString()} IP packets · {pcapReport.connectionCount.toLocaleString()} connections</span>
                      </div>
                      {pcapReport.nonIpPackets > 0 && <p className="registry-analysis-copy">{pcapReport.nonIpPackets.toLocaleString()} non-IP packets were not included in the IP summaries.</p>}
                      {pcapReport.packetDetailsTruncated && <p className="registry-warning">Packet detail display is limited to the first 1,000 IP packets; summary counts include all parsed IP packets.</p>}
                      {pcapReport.leads.length > 0 && (
                        <div className="pcap-leads" aria-label="Suspicious indicators for analyst review">
                          <strong>Suspicious indicators — leads, not confirmed threats</strong>
                          {pcapReport.leads.map((lead, index) => (
                            <p key={`${lead.indicator}-${index}`}>
                              <b>{lead.classification}</b>
                              <span>{lead.indicator}: {lead.sourceIp} → {lead.destinationIp} ({lead.distinctDestinationPorts} destination ports)</span>
                              <small>{lead.note}</small>
                            </p>
                          ))}
                        </div>
                      )}
                      {pcapReport.warnings.map((warning) => <p className="registry-warning" key={warning}>{warning}</p>)}
                      <h4 className="pcap-subheading">Connection summaries (first 100)</h4>
                      <div className="pcap-table-wrap">
                        <table className="pcap-table">
                          <thead><tr><th>Protocol</th><th>Endpoint A</th><th>Endpoint B</th><th>Packets</th><th>Bytes</th><th>First / last seen</th></tr></thead>
                          <tbody>
                            {pcapReport.connections.slice(0, 100).map((connection, index) => (
                              <tr key={`${connection.endpointA}-${connection.endpointB}-${connection.protocol}-${index}`}>
                                <td>{connection.protocol}</td>
                                <td>{connection.endpointA}</td>
                                <td>{connection.endpointB}</td>
                                <td>{connection.packets}</td>
                                <td>{connection.bytes}</td>
                                <td>{connection.firstSeen || 'Timestamp unavailable'}<br />{connection.lastSeen || 'Timestamp unavailable'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <h4 className="pcap-subheading">Packet details (first 100)</h4>
                      <div className="pcap-table-wrap">
                        <table className="pcap-table">
                          <thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th></tr></thead>
                          <tbody>
                            {pcapReport.packets.slice(0, 100).map((packet, index) => (
                              <tr key={`${packet.timestamp}-${packet.sourceIp}-${packet.destinationIp}-${index}`}>
                                <td>{packet.timestamp || 'Timestamp unavailable'}</td>
                                <td>{packet.sourceIp}:{packet.sourcePort ?? '—'}</td>
                                <td>{packet.destinationIp}:{packet.destinationPort ?? '—'}</td>
                                <td>{packet.protocol}</td>
                                <td>{packet.bytes}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {pcapReport.connections.length > 100 && <p className="registry-analysis-copy">Connection table display is limited to the first 100 summaries.</p>}
                      <form className="exif-validation-form" onSubmit={savePcapReport}>
                        <label htmlFor="pcap-validation-status">Analyst validation</label>
                        <select id="pcap-validation-status" value={pcapValidationStatus} onChange={(event) => setPcapValidationStatus(event.target.value)}>
                          <option>VERIFIED</option>
                          <option>MISMATCH</option>
                          <option>NEEDS REVIEW</option>
                        </select>
                        <label htmlFor="pcap-analyst">Analyst</label>
                        <input id="pcap-analyst" value={pcapAnalyst} onChange={(event) => setPcapAnalyst(event.target.value)} required />
                        <label htmlFor="pcap-notes">Analyst notes</label>
                        <textarea id="pcap-notes" value={pcapNotes} onChange={(event) => setPcapNotes(event.target.value)} rows="3" />
                        <label htmlFor="pcap-artifact-references">Artifact references</label>
                        <textarea id="pcap-artifact-references" value={pcapArtifactReferences} onChange={(event) => setPcapArtifactReferences(event.target.value)} rows="2" placeholder="One reference per line" />
                        <button type="submit" className="button button-dark" disabled={busy || !pcapAnalyst.trim() || Boolean(selectedRecord.archivedAt)}>Save analysis report</button>
                      </form>
                    </>
                  )}
                  {selectedRecord.pcapAnalysis && (
                    <div className="registry-saved-report">
                      <strong>Saved validation: {selectedRecord.pcapAnalysis.status}</strong>
                      <span>Analyst: {selectedRecord.pcapAnalysis.analyst}</span>
                      <button type="button" className="text-button" onClick={downloadPcapReport}>Download PCAP analysis and custody report</button>
                    </div>
                  )}
                  {pcapReport?.leads.length > 0 && <p className="pcap-disclaimer">Leads are heuristic indicators for analyst review, not confirmed threats.</p>}
                </section>

                <section className="registry-analysis-section sqlite-analysis-section" aria-label="SQLite database analysis" hidden={activeWorkspace !== 'sqlite'}>
                  <div className="detail-section-title">
                    <h3>SQLite database analysis</h3>
                    <span>READ ONLY · LOCAL</span>
                  </div>
                  <p className="registry-analysis-copy">Analyze a hash-verified copy in an in-memory, query-only database. Source evidence and its SHA-256 are preserved.</p>
                  <button type="button" className="button button-dark" onClick={analyzeSqliteDatabase} disabled={busy || Boolean(selectedRecord.archivedAt)}>
                    {busy ? 'Analyzing…' : 'Analyze selected database'}
                  </button>
                  {sqliteReport && (
                    <>
                      <div className="registry-analysis-summary">
                        <strong>SQLite · user version {sqliteReport.userVersion}</strong>
                        <span>{sqliteReport.tableCount} tables · {sqliteReport.viewCount} views · {sqliteReport.recordCount.toLocaleString()} records</span>
                      </div>
                      {sqliteReport.warnings.map((warning) => <p className="registry-warning" key={warning}>{warning}</p>)}
                      <div className="sqlite-objects">
                        {sqliteReport.tables.map((table) => (
                          <details className="sqlite-object" key={`${table.type}-${table.name}`}>
                            <summary>{table.name} <span>{table.type} · {table.records.length} records{table.recordLimitReached ? ' · limited' : ''}</span></summary>
                            <p className="registry-analysis-copy">Schema: {table.schemaSql || 'No SQL definition available'}</p>
                            <h4 className="pcap-subheading">Columns</h4>
                            <div className="pcap-table-wrap">
                              <table className="pcap-table">
                                <thead><tr><th>Name</th><th>Type</th><th>Required</th><th>Primary key</th><th>Default</th></tr></thead>
                                <tbody>
                                  {table.columns.map((column) => (
                                    <tr key={column.name}>
                                      <td>{column.name}</td><td>{column.type || '—'}</td><td>{column.notNull ? 'Yes' : 'No'}</td><td>{column.primaryKey ? 'Yes' : 'No'}</td><td>{column.defaultValue === null ? '—' : JSON.stringify(column.defaultValue)}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                            {table.timestampFields.length > 0 && (
                              <>
                                <h4 className="pcap-subheading">Timestamp field candidates</h4>
                                <ul className="sqlite-timestamp-list">
                                  {table.timestampFields.map((field) => (
                                    <li key={field.column}>
                                      <strong>{field.column}</strong>
                                      <span>{field.hasRecognizedValues ? field.examples.map((example) => `${JSON.stringify(example.raw)} → ${example.iso} (${example.reason})`).join('; ') : 'No recognized timestamp values in the returned records'}</span>
                                    </li>
                                  ))}
                                </ul>
                              </>
                            )}
                            <h4 className="pcap-subheading">Records (first 20 returned)</h4>
                            <div className="pcap-table-wrap">
                              <table className="pcap-table">
                                <thead><tr>{table.columns.map((column) => <th key={column.name}>{column.name}</th>)}</tr></thead>
                                <tbody>
                                  {table.records.slice(0, 20).map((row, rowIndex) => (
                                    <tr key={rowIndex}>
                                      {table.columns.map((column) => {
                                        const value = row[column.name];
                                        return <td key={column.name}>{value === null ? 'NULL' : typeof value === 'object' ? JSON.stringify(value) : String(value)}</td>;
                                      })}
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </details>
                        ))}
                      </div>
                      <form className="exif-validation-form" onSubmit={saveSqliteReport}>
                        <label htmlFor="sqlite-validation-status">Analyst validation</label>
                        <select id="sqlite-validation-status" value={sqliteValidationStatus} onChange={(event) => setSqliteValidationStatus(event.target.value)}>
                          <option>VERIFIED</option>
                          <option>MISMATCH</option>
                          <option>NEEDS REVIEW</option>
                        </select>
                        <label htmlFor="sqlite-analyst">Analyst</label>
                        <input id="sqlite-analyst" value={sqliteAnalyst} onChange={(event) => setSqliteAnalyst(event.target.value)} required />
                        <label htmlFor="sqlite-notes">Analyst notes</label>
                        <textarea id="sqlite-notes" value={sqliteNotes} onChange={(event) => setSqliteNotes(event.target.value)} rows="3" />
                        <label htmlFor="sqlite-artifact-references">Artifact references</label>
                        <textarea id="sqlite-artifact-references" value={sqliteArtifactReferences} onChange={(event) => setSqliteArtifactReferences(event.target.value)} rows="2" placeholder="One reference per line" />
                        <button type="submit" className="button button-dark" disabled={busy || !sqliteAnalyst.trim() || Boolean(selectedRecord.archivedAt)}>Save analysis report</button>
                      </form>
                    </>
                  )}
                  {selectedRecord.sqliteAnalysis && (
                    <div className="registry-saved-report">
                      <strong>Saved validation: {selectedRecord.sqliteAnalysis.status}</strong>
                      <span>Analyst: {selectedRecord.sqliteAnalysis.analyst}</span>
                      <button type="button" className="text-button" onClick={downloadSqliteReport}>Download SQLite analysis and custody report</button>
                    </div>
                  )}
                </section>

                <div className="custody-section" hidden={analysisWorkspace && activeWorkspace !== 'exif'}>
                  <div className="detail-section-title"><h3>Chain of custody</h3><span>{selectedRecord.custody.length} EVENTS</span></div>
                  <ol className="custody-list">
                    {selectedRecord.custody.slice().reverse().map((entry) => (
                      <li key={entry.eventHash}>
                        <span className="timeline-dot"><Icon name="clock" size={13} /></span>
                        <div className="event-copy">
                          <strong>{entry.action}</strong>
                          <span>{entry.actor}</span>
                          <time dateTime={entry.timestamp}>{formatDate(entry.timestamp)}</time>
                          {entry.details && (
                            <small className="evidence-audit-details">
                              {entry.details.reason && `Reason: ${entry.details.reason}`}
                              {entry.details.originalEvidenceId && ` · Original ID: ${entry.details.originalEvidenceId}`}
                              {entry.details.replacementEvidenceId && ` · Replacement ID: ${entry.details.replacementEvidenceId}`}
                            </small>
                          )}
                          <code>{entry.eventHash.slice(0, 16)}…</code>
                        </div>
                      </li>
                    ))}
                  </ol>
                  <form className="custody-form" onSubmit={logCustodyEvent}>
                    <label htmlFor="custody-action">Record an event</label>
                    <div className="custody-controls">
                      <select id="custody-action" value={custodyAction} onChange={(event) => setCustodyAction(event.target.value)}>
                        <option>Evidence reviewed</option>
                        <option>Evidence transferred</option>
                        <option>Evidence accessed</option>
                        <option>Evidence returned to storage</option>
                      </select>
                      <button type="submit" className="icon-button record-event-button" disabled={busy || !custodian.trim() || Boolean(selectedRecord.archivedAt)} aria-label="Record custody event" title="Record custody event"><Icon name="plus" size={17} /></button>
                    </div>
                  </form>
                </div>
              </>
            ) : (
              <div className="detail-placeholder">
                <span className="placeholder-lock"><Icon name="lock" size={21} /></span>
                <h3>Evidence details</h3>
                <p>{records.length ? 'Select a file to inspect its metadata and custody record.' : 'File metadata, cryptographic fingerprints, and custody events will appear here.'}</p>
              </div>
            )}
          </section>
        </div>}

        <footer className="workspace-footer">
          <span><Icon name="lock" size={14} /> Files and metadata stay in this browser</span>
          <span>Local browser storage is not a tamper-proof or court-certified evidence system.</span>
        </footer>
      </main>
      </div>
      <button
        ref={copilotLauncherRef}
        type="button"
        className="copilot-floating-launcher"
        aria-label={copilotPanelOpen ? 'Close AI Copilot chat' : 'Open AI Copilot chat'}
        aria-controls="copilot-chat-panel"
        aria-expanded={copilotPanelOpen}
        title={copilotPanelOpen ? 'Close AI Forensic Copilot' : 'Open AI Forensic Copilot'}
        onClick={() => {
          if (copilotPanelOpen) closeCopilotPanel();
          else {
            setCopilotPanelMinimized(false);
            setCopilotPanelOpen(true);
          }
        }}
      >
        <Icon name="sparkles" size={25} />
      </button>
    </div>
  );
}

export default App;
