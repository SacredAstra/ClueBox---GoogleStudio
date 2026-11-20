import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI, Type } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT) || 3000;
const MODEL_NAME = 'gemini-4-hydrogen';

const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  })
  : null;

const claimSchema = {
  type: Type.OBJECT,
  properties: {
    text: { type: Type.STRING, description: 'Clear, objective forensic statement grounded strictly in cited evidence facts.' },
    evidenceRefs: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: 'Exact evidence reference IDs (e.g. "E1", "E2") supporting this statement.',
    },
  },
  required: ['text', 'evidenceRefs'],
};

const workflowStepSchema = {
  type: Type.OBJECT,
  properties: {
    step: { type: Type.INTEGER, description: 'Sequential step number starting at 1.' },
    title: { type: Type.STRING, description: 'Concise action step title.' },
    action: { type: Type.STRING, description: 'Concrete forensic procedure or verification step for the investigator.' },
    module: { type: Type.STRING, description: 'Target ClueBox Odyssey toolkit module (e.g. EXIF Analysis, Windows Registry, PCAP Analysis, SQLite Analysis, Investigation Timeline, Evidence Locker, Reports).' },
    evidenceRefs: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: 'Supporting evidence reference IDs (e.g. "E1").',
    },
  },
  required: ['step', 'title', 'action', 'module', 'evidenceRefs'],
};

const analyzedTimelineItemSchema = {
  type: Type.OBJECT,
  properties: {
    timestamp: { type: Type.STRING, description: 'Normalized UTC timestamp or exact original/ambiguous timestamp string preserved from source records.' },
    eventSummary: { type: Type.STRING, description: 'Concise description of the observed event.' },
    analysis: { type: Type.STRING, description: 'Analytic context, behavioral meaning, or cross-artifact correlation for this timeline entry.' },
    significance: { type: Type.STRING, description: 'Priority level: HIGH, MEDIUM, or LOW.' },
    evidenceRefs: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: 'Supporting evidence reference IDs (e.g. "E1").',
    },
  },
  required: ['timestamp', 'eventSummary', 'analysis', 'significance', 'evidenceRefs'],
};

const unsupportedClaimSchema = {
  type: Type.OBJECT,
  properties: {
    category: { type: Type.STRING },
    text: { type: Type.STRING },
    reason: { type: Type.STRING },
  },
  required: ['category', 'text', 'reason'],
};

const copilotResponseSchema = {
  type: Type.OBJECT,
  properties: {
    summary: { type: Type.STRING, description: 'Concise executive forensic overview grounded strictly in the provided records and logs.' },
    objectiveConclusions: {
      type: Type.ARRAY,
      items: claimSchema,
      description: 'Objective, fact-bound conclusions directly supported by the observed evidence, metadata, hashes, and logs.',
    },
    interpretations: {
      type: Type.ARRAY,
      items: claimSchema,
      description: 'Analytic forensic statements interpreting observed artifacts without fabricating unrecorded facts.',
    },
    connections: {
      type: Type.ARRAY,
      items: claimSchema,
      description: 'Explicit cross-artifact, cross-module, or log-to-evidence connections (timestamps, custody links, hashes, endpoints, registry paths, database rows).',
    },
    investigativeLeads: {
      type: Type.ARRAY,
      items: claimSchema,
      description: 'Actionable investigative leads and hypotheses requiring human verification.',
    },
    recommendations: {
      type: Type.ARRAY,
      items: claimSchema,
      description: 'Viable next steps for the investigator or custodian.',
    },
    workflow: {
      type: Type.ARRAY,
      items: workflowStepSchema,
      description: 'Ordered forensic workflow laying out concrete next steps across ClueBox Odyssey modules.',
    },
    analyzedTimeline: {
      type: Type.ARRAY,
      items: analyzedTimelineItemSchema,
      description: 'Chronological AI-analyzed timeline entries correlating evidence, custody logs, and forensic module timestamps while preserving timestamp uncertainty.',
    },
    gapsAndAnomalies: {
      type: Type.ARRAY,
      items: claimSchema,
      description: 'Observed timestamp ambiguities, integrity/custody gaps, unanalyzed artifacts, or evidentiary limitations.',
    },
    insufficientEvidence: {
      type: Type.BOOLEAN,
      description: 'True if the provided facts are insufficient to answer part or all of the question.',
    },
    unsupportedClaims: {
      type: Type.ARRAY,
      items: unsupportedClaimSchema,
      description: 'Any requested claim or hypothesis that cannot be supported by the supplied facts.',
    },
  },
  required: [
    'summary',
    'objectiveConclusions',
    'interpretations',
    'connections',
    'investigativeLeads',
    'recommendations',
    'workflow',
    'analyzedTimeline',
    'gapsAndAnomalies',
    'insufficientEvidence',
    'unsupportedClaims',
  ],
};

const SYSTEM_INSTRUCTION = [
  'You are the AI Forensic Copilot inside ClueBox Odyssey, an analytical and observatory digital forensics assistant.',
  'You have read-only observatory access to verified case facts, evidence inventory, EXIF metadata, Windows Registry artifacts, PCAP network captures, SQLite databases, chain-of-custody logs, saved analyst validations, and timeline records supplied in the request.',
  'STRICT FORENSIC RULES:',
  '1. Every single item in objectiveConclusions, interpretations, connections, investigativeLeads, recommendations, workflow, analyzedTimeline, and gapsAndAnomalies MUST cite one or more EXACT referenceId values from the provided facts array (for example ["E1"] or ["E1", "E4"]).',
  '2. NEVER invent facts, timestamps, IP addresses, file hashes, registry keys, or reference IDs that are not present in the provided facts.',
  '3. Preserve timestamp ambiguity: never silently convert timezone-ambiguous EXIF or local timestamps to UTC; explicitly note uncertainty.',
  '4. Distinguish objective evidence-bound observations from investigative leads and hypotheses. Remind clearly through structured fields that all AI outputs require independent custodian/investigator verification.',
  '5. Provide concrete, viable next steps and a logical multi-step workflow referencing ClueBox Odyssey toolkit modules (Evidence Locker, EXIF Analysis, Windows Registry, PCAP Analysis, SQLite Analysis, Investigation Timeline, Reports).',
  '6. Keep every individual claim concise (under 800 characters) and limit each array to at most 12 high-value items.',
].join('\n');

function sanitizeAnalystId(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return `custodian:${slug || 'investigator'}`;
}

async function generateForensicAnalysis({
  mode,
  caseNumber,
  caseDetails,
  question,
  facts,
  timelineEvents,
  toolkitSummary,
}: {
  mode: 'ask' | 'analyze_timeline';
  caseNumber: string;
  caseDetails?: Record<string, unknown> | null;
  question: string;
  facts: Array<Record<string, unknown>>;
  timelineEvents?: Array<Record<string, unknown>>;
  toolkitSummary?: Record<string, unknown> | null;
}) {
  if (!ai) {
    const err = new Error('AI Copilot unavailable — GEMINI_API_KEY is not configured in server secrets.');
    (err as Error & { statusCode?: number }).statusCode = 503;
    throw err;
  }

  const promptPayload = {
    mode,
    caseNumber,
    caseDetails: caseDetails || null,
    toolkitSummary: toolkitSummary || null,
    question,
    factCount: facts.length,
    facts,
    timelineEventCount: Array.isArray(timelineEvents) ? timelineEvents.length : 0,
    timelineEvents: Array.isArray(timelineEvents) ? timelineEvents.slice(0, 100) : [],
  };

  const directive = mode === 'analyze_timeline'
    ? 'Perform a comprehensive forensic timeline analysis across all supplied case logs, custody chains, evidence metadata, toolkit outputs, and timeline events. Produce an AI-analyzed chronological view highlighting cross-artifact connections, gaps/anomalies, objective conclusions, and a recommended verification workflow.'
    : 'Answer the investigator question using full observatory visibility across the supplied case facts, logs, toolkit records, and timeline events. Produce objective conclusions, analytic statements, explicit connections, viable next steps, a structured workflow, and relevant timeline analysis.';

  const response = await ai.models.generateContent({
    model: MODEL_NAME,
    contents: `${directive}\n\nCASE EVIDENCE & LOG CONTEXT (JSON):\n${JSON.stringify(promptPayload)}`,
    config: {
      systemInstruction: SYSTEM_INSTRUCTION,
      responseMimeType: 'application/json',
      responseSchema: copilotResponseSchema,
    },
  });

  const text = response.text?.trim();
  if (!text) {
    throw new Error('The AI service returned an empty analysis response.');
  }
  return JSON.parse(text);
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  app.post('/api/copilot', async (req, res) => {
    req.setTimeout(310_000);
    res.setTimeout(310_000);
    try {
      const { action } = req.body || {};

      if (action === 'status') {
        const available = Boolean(ai);
        return res.json({
          available,
          provider: 'gemini',
          model: MODEL_NAME,
          message: available
            ? 'AI Forensic Copilot ready — full toolkit observatory & human-verification workflow active.'
            : 'AI Copilot unavailable — configure GEMINI_API_KEY in Settings > Secrets.',
        });
      }

      if (action === 'authorize_validation') {
        const investigator = typeof req.body?.investigator === 'string'
          ? req.body.investigator.trim().slice(0, 120)
          : '';
        if (!investigator) {
          return res.status(400).json({
            error: 'Enter the custodian or investigator name to verify and sign off on AI findings.',
          });
        }
        return res.json({
          authorized: true,
          investigator,
          investigatorId: sanitizeAnalystId(investigator),
        });
      }

      if (action === 'ask' || action === 'analyze_timeline') {
        const caseNumber = typeof req.body?.caseNumber === 'string' ? req.body.caseNumber.trim() : '';
        const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
        const facts = Array.isArray(req.body?.facts) ? req.body.facts : [];
        const timelineEvents = Array.isArray(req.body?.timelineEvents) ? req.body.timelineEvents : [];
        const caseDetails = req.body?.caseDetails && typeof req.body.caseDetails === 'object' ? req.body.caseDetails : null;
        const toolkitSummary = req.body?.toolkitSummary && typeof req.body.toolkitSummary === 'object' ? req.body.toolkitSummary : null;

        if (!facts.length) {
          return res.status(400).json({ error: 'At least one verified evidence or log fact is required for AI analysis.' });
        }

        const effectiveQuestion = question || (action === 'analyze_timeline'
          ? 'Analyze the complete chronological timeline, correlate all forensic logs and custody events, identify gaps or anomalies, and outline verification next steps.'
          : 'Analyze all selected case records and logs, provide objective conclusions, connections, viable next steps, and a workflow.');

        const result = await generateForensicAnalysis({
          mode: action,
          caseNumber,
          caseDetails,
          question: effectiveQuestion,
          facts,
          timelineEvents,
          toolkitSummary,
        });
        return res.json(result);
      }

      return res.status(400).json({ error: `Unsupported Copilot action "${String(action || '')}".` });
    } catch (error) {
      const err = error as Error & { statusCode?: number; status?: number };
      const status = err.statusCode || (typeof err.status === 'number' && err.status >= 400 && err.status < 600 ? err.status : 500);
      console.error('[/api/copilot] Error:', err);
      return res.status(status).json({
        error: err.message || 'The AI Forensic Copilot request failed.',
      });
    }
  });

  const isProd = process.env.NODE_ENV === 'production';
  const distDir = path.resolve(__dirname, 'dist');

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else if (fs.existsSync(distDir)) {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`ClueBox Odyssey server listening on http://0.0.0.0:${PORT}`);
  });
  server.requestTimeout = 310_000;
  server.headersTimeout = 315_000;
  server.keepAliveTimeout = 310_000;
}

startServer().catch((err) => {
  console.error('Failed to start ClueBox Odyssey server:', err);
  process.exit(1);
});
