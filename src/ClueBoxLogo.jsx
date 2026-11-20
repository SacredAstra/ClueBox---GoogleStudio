import { useId } from 'react';

export default function ClueBoxLogo({ size = 48, className = '', decorative = false }) {
  const uid = useId().replace(/:/g, '');
  const strokeGradId = `cb-stroke-${uid}`;
  const fillGradId = `cb-fill-${uid}`;
  const glowGradId = `cb-glow-${uid}`;

  return (
    <svg
      className={className || undefined}
      width={size}
      height={size}
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role={decorative ? undefined : 'img'}
      aria-label={decorative ? undefined : 'ClueBox Odyssey mystery box and digital fingerprint logo'}
      aria-hidden={decorative ? 'true' : undefined}
    >
      <defs>
        <linearGradient id={strokeGradId} x1="16" y1="14" x2="104" y2="106" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#67e8f9" />
          <stop offset="50%" stopColor="#22d3ee" />
          <stop offset="100%" stopColor="#8b5cf6" />
        </linearGradient>
        <linearGradient id={fillGradId} x1="18" y1="14" x2="102" y2="108" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#122645" />
          <stop offset="100%" stopColor="#091020" />
        </linearGradient>
        <radialGradient id={glowGradId} cx="50%" cy="46%" r="48%">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0" />
        </radialGradient>
      </defs>

      <polygon
        points="60,8 106,34 106,86 60,112 14,86 14,34"
        fill={`url(#${fillGradId})`}
        stroke={`url(#${strokeGradId})`}
        strokeWidth="3.5"
        strokeLinejoin="round"
      />
      <polygon
        points="60,8 106,34 60,60 14,34"
        fill={`url(#${glowGradId})`}
      />
      <polyline
        points="14,34 60,60 106,34"
        stroke={`url(#${strokeGradId})`}
        strokeWidth="2.5"
        strokeLinejoin="round"
        opacity="0.72"
      />
      <line
        x1="60"
        y1="60"
        x2="60"
        y2="112"
        stroke={`url(#${strokeGradId})`}
        strokeWidth="2.5"
        opacity="0.52"
      />

      {/* Digital fingerprint arcs inside the mystery cube */}
      <path
        d="M42 56 C42 44 50 36 60 36 C70 36 78 44 78 56 C78 69 72 79 60 87"
        stroke="#67e8f9"
        strokeWidth="3"
        strokeLinecap="round"
      />
      <path
        d="M48 58 C48 49.5 53.2 43.5 60 43.5 C66.8 43.5 72 49.5 72 58 C72 67 67 74.5 58 80"
        stroke="#22d3ee"
        strokeWidth="3"
        strokeLinecap="round"
      />
      <path
        d="M54 59 C54 54.2 56.6 50.5 60 50.5 C63.4 50.5 66 54.2 66 59 C66 64.5 62.5 69.5 56 73"
        stroke="#a78bfa"
        strokeWidth="3"
        strokeLinecap="round"
      />
      <circle cx="60" cy="23" r="3.2" fill="#67e8f9" />
      <circle cx="42" cy="64" r="2.2" fill="#38bdf8" />
      <circle cx="78" cy="64" r="2.2" fill="#8b5cf6" />
    </svg>
  );
}
