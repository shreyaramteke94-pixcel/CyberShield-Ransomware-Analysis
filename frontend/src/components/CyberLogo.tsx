import React from 'react';

interface CyberLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showSubtitle?: boolean;
  align?: 'left' | 'center';
  className?: string;
}

export const CyberLogo: React.FC<CyberLogoProps> = ({
  size = 'md',
  showSubtitle = true,
  align = 'left',
  className = ''
}) => {
  const isCenter = align === 'center';

  const iconSizes = {
    sm: { w: 22, h: 26 },
    md: { w: 28, h: 32 },
    lg: { w: 36, h: 42 },
    xl: { w: 48, h: 56 }
  };

  const titleSizes = {
    sm: 'text-sm font-semibold tracking-tight',
    md: 'text-base font-semibold tracking-tight',
    lg: 'text-xl font-bold tracking-tight',
    xl: 'text-2xl font-bold tracking-tight'
  };

  const subtitleSizes = {
    sm: 'text-[10px]',
    md: 'text-[11px]',
    lg: 'text-xs',
    xl: 'text-xs'
  };

  const currentSize = iconSizes[size];

  return (
    <div className={`flex ${isCenter ? 'flex-col items-center text-center' : 'items-center gap-3'} ${className}`} id="cybershield-brand-logo">
      {/* Bespoke Geometric Shield + Digital Circuit + Intelligence Pulse SVG */}
      <div className="relative flex-shrink-0 flex items-center justify-center">
        <svg
          width={currentSize.w}
          height={currentSize.h}
          viewBox="0 0 40 48"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="transition-transform duration-200 hover:scale-105"
        >
          <defs>
            {/* Primary Gradient */}
            <linearGradient id="shieldGrad" x1="20" y1="2" x2="20" y2="46" gradientUnits="userSpaceOnUse">
              <stop stopColor="#3B82F6" />
              <stop offset="1" stopColor="#1D4ED8" />
            </linearGradient>

            {/* Cyan Accent Gradient */}
            <linearGradient id="cyanGrad" x1="8" y1="12" x2="32" y2="36" gradientUnits="userSpaceOnUse">
              <stop stopColor="#22D3EE" />
              <stop offset="1" stopColor="#3B82F6" />
            </linearGradient>

            {/* Inner Dark Background */}
            <linearGradient id="innerShieldBg" x1="20" y1="5" x2="20" y2="43" gradientUnits="userSpaceOnUse">
              <stop stopColor="#111C2E" />
              <stop offset="1" stopColor="#0B1220" />
            </linearGradient>
          </defs>

          {/* Outer Shield Geometry */}
          <path
            d="M20 2L36 8.5V21C36 32.5 29.2 41.5 20 46C10.8 41.5 4 32.5 4 21V8.5L20 2Z"
            fill="url(#innerShieldBg)"
            stroke="url(#shieldGrad)"
            strokeWidth="2"
            strokeLinejoin="round"
          />

          {/* Inner Shield Accent Contour */}
          <path
            d="M20 6.5L32 11.5V21C32 29.8 26.8 37.2 20 41C13.2 37.2 8 29.8 8 21V11.5L20 6.5Z"
            fill="none"
            stroke="#24344D"
            strokeWidth="1"
          />

          {/* Digital Circuit Patterns */}
          {/* Top connection node */}
          <line x1="20" y1="7" x2="20" y2="14" stroke="#22D3EE" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="20" cy="14" r="1.5" fill="#22D3EE" />

          {/* Left circuit branch */}
          <path
            d="M13 18H17L20 22"
            stroke="#3B82F6"
            strokeWidth="1.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <circle cx="13" cy="18" r="1.2" fill="#3B82F6" />

          {/* Right circuit branch */}
          <path
            d="M27 18H23L20 22"
            stroke="#3B82F6"
            strokeWidth="1.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <circle cx="27" cy="18" r="1.2" fill="#3B82F6" />

          {/* Active Threat Detection Pulse / Lightning Line */}
          <path
            d="M14 26.5H18.5L20.5 20.5L22 30L24 26.5H26.5"
            stroke="url(#cyanGrad)"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Central Active Intelligence Core Node */}
          <circle cx="20" cy="24" r="2.2" fill="#22D3EE" />
          <circle cx="20" cy="24" r="4" stroke="#22D3EE" strokeWidth="0.8" opacity="0.4" />

          {/* Bottom Root Anchor */}
          <path
            d="M20 33V38"
            stroke="#3B82F6"
            strokeWidth="1.2"
            strokeLinecap="round"
          />
          <circle cx="20" cy="38" r="1.2" fill="#22D3EE" />
        </svg>
      </div>

      {/* Brand Text Block */}
      <div className={`flex flex-col ${isCenter ? 'items-center' : 'items-start'}`}>
        <div className="flex items-center gap-1.5 leading-none">
          <span className={`text-[#F8FAFC] ${titleSizes[size]}`}>
            CyberShield
          </span>
          <span className="w-1.5 h-1.5 rounded-full bg-[#22D3EE] inline-block" />
        </div>
        {showSubtitle && (
          <span className={`text-[#94A3B8] font-normal mt-1 leading-tight ${subtitleSizes[size]}`}>
            Intelligent Security. Stronger Protection.
          </span>
        )}
      </div>
    </div>
  );
};
