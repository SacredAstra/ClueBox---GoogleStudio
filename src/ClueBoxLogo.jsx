const LOGO_SRC = '/assets/aistudio/image_776a4a67.png';

export default function ClueBoxLogo({ size = 48, className = '', decorative = false }) {
  const combinedClassName = className ? `cluebox-logo-img ${className}` : 'cluebox-logo-img';

  return (
    <img
      src={LOGO_SRC}
      className={combinedClassName}
      width={size}
      height={size}
      alt={decorative ? '' : 'ClueBox Odyssey mystery box and digital fingerprint logo'}
      aria-hidden={decorative ? 'true' : undefined}
    />
  );
}
