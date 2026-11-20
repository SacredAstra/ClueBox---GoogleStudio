const STORAGE_KEY = 'forensiai.navigation.v1';

const VALID_WORKSPACES = new Set([
  'overview',
  'cases',
  'evidence',
  'exif',
  'registry',
  'pcap',
  'sqlite',
  'timeline',
  'reports',
]);

const DEFAULT_STATE = {
  entered: false,
  workspace: 'overview',
  caseId: '',
  selectedId: '',
};

export function readNavigationState() {
  try {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return { ...DEFAULT_STATE };
    }
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_STATE };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { ...DEFAULT_STATE };
    return {
      entered: parsed.entered === true,
      workspace: VALID_WORKSPACES.has(parsed.workspace) ? parsed.workspace : 'overview',
      caseId: typeof parsed.caseId === 'string' ? parsed.caseId : '',
      selectedId: typeof parsed.selectedId === 'string' ? parsed.selectedId : '',
    };
  } catch {
    return { ...DEFAULT_STATE };
  }
}

export function writeNavigationState(state) {
  try {
    if (typeof window === 'undefined' || !window.sessionStorage) return false;
    const normalized = {
      entered: state?.entered === true,
      workspace: VALID_WORKSPACES.has(state?.workspace) ? state.workspace : 'overview',
      caseId: typeof state?.caseId === 'string' ? state.caseId : '',
      selectedId: typeof state?.selectedId === 'string' ? state.selectedId : '',
    };
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(normalized));
    return true;
  } catch {
    return false;
  }
}
