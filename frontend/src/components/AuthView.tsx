import React, { useState } from 'react';
import { UserProfile } from '../types';
import { 
  User, 
  Lock, 
  Check, 
  Eye, 
  EyeOff, 
  AlertCircle,
  Shield,
  ArrowRight
} from 'lucide-react';

interface AuthViewProps {
  onLogin: (user: UserProfile) => void;
}

export const AuthView: React.FC<AuthViewProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('admin@cybershield.sec');
  const [password, setPassword] = useState('••••••••••••');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [isForgotOpen, setIsForgotOpen] = useState(false);
  const [forgotSent, setForgotSent] = useState(false);

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');

    if (!username || !password) {
      setErrorMsg('Please enter both username and password.');
      return;
    }

    const authenticatedUser: UserProfile = {
      id: 'usr-auth-01',
      name: username.includes('@') ? username.split('@')[0] : 'Administrator',
      email: username.includes('@') ? username : `${username}@cybershield.sec`,
      role: 'Security Admin',
      avatar: '',
      badge: 'ADMIN',
      lastLogin: 'Just now',
      analysesCount: 1428
    };

    onLogin(authenticatedUser);
  };

  const handleGoogleSignIn = () => {
    onLogin({
      id: 'usr-google-auth',
      name: 'Security Administrator',
      email: 'admin@cybershield.sec',
      role: 'Security Admin',
      avatar: '',
      badge: 'ADMIN',
      lastLogin: 'Just now',
      analysesCount: 1428
    });
  };

  return (
    <div 
      className="min-h-screen w-full flex items-center justify-center px-4 py-8 relative overflow-hidden select-none"
      id="cybershield-auth-view"
      style={{
        background: 'radial-gradient(ellipse at 50% 30%, #0d274c 0%, #08172e 45%, #040a14 100%)'
      }}
    >
      {/* Ambient background soft light orbs */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[#1a4b85]/20 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-10 right-1/4 w-[400px] h-[400px] bg-[#0c315c]/25 rounded-full blur-[100px] pointer-events-none" />

      {/* Main Glassmorphism Card (matching the reference template) */}
      <div className="relative w-full max-w-[390px] z-10">
        
        {/* Glowing Edge Flares / Lens Lights matching reference image */}
        <div className="absolute top-[38%] -left-[3px] w-2 h-16 bg-[#38bdf8] rounded-full blur-[3px] opacity-90 pointer-events-none" />
        <div className="absolute top-[36%] -left-[8px] w-6 h-20 bg-[#38bdf8]/40 rounded-full blur-[10px] pointer-events-none" />
        
        <div className="absolute top-[52%] -right-[3px] w-2 h-18 bg-[#38bdf8] rounded-full blur-[3px] opacity-90 pointer-events-none" />
        <div className="absolute top-[50%] -right-[8px] w-6 h-24 bg-[#38bdf8]/40 rounded-full blur-[10px] pointer-events-none" />

        {/* Glass Container */}
        <div 
          className="relative rounded-[36px] p-8 sm:p-10 shadow-2xl transition-all"
          style={{
            background: 'linear-gradient(145deg, rgba(14, 55, 102, 0.45) 0%, rgba(8, 30, 60, 0.55) 100%)',
            backdropFilter: 'blur(28px)',
            WebkitBackdropFilter: 'blur(28px)',
            border: '1.5px solid rgba(56, 189, 248, 0.45)',
            boxShadow: `
              0 20px 50px rgba(2, 6, 23, 0.7),
              inset 0 1px 2px rgba(255, 255, 255, 0.3),
              inset 0 0 25px rgba(56, 189, 248, 0.15)
            `
          }}
        >
          {/* Top Circular Outline with Security Icon */}
          <div className="flex flex-col items-center justify-center pt-2 pb-8">
            <div 
              className="w-24 h-24 rounded-full flex items-center justify-center relative transition-transform duration-300 hover:scale-105"
              style={{
                border: '2px solid #38bdf8',
                boxShadow: '0 0 20px rgba(56, 189, 248, 0.35), inset 0 0 15px rgba(56, 189, 248, 0.2)',
                background: 'rgba(6, 24, 48, 0.4)'
              }}
            >
              {/* CyberShield Custom Geometric Icon */}
              <div className="relative flex items-center justify-center">
                <Shield className="w-10 h-10 text-[#38bdf8] stroke-[1.5]" />
                <div className="absolute w-2 h-2 rounded-full bg-[#38bdf8] shadow-[0_0_8px_#38bdf8]" />
              </div>
            </div>

            <h1 className="text-sm font-semibold tracking-wider text-[#e0f2fe] uppercase mt-3.5 opacity-90">
              CyberShield
            </h1>
            <span className="text-[10px] text-[#7dd3fc]/80 tracking-wide mt-0.5 font-light">
              Intelligent Security. Stronger Protection.
            </span>
          </div>

          {/* Error notification */}
          {errorMsg && (
            <div className="mb-4 p-2.5 rounded-lg bg-[#ef4444]/20 border border-[#ef4444]/40 text-[#fca5a5] text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Form Fields */}
          <form onSubmit={handleLoginSubmit} className="space-y-4">
            
            {/* Username Input Field */}
            <div 
              className="flex items-center gap-3.5 px-4 py-3 rounded-lg transition-all focus-within:ring-1 focus-within:ring-[#38bdf8]"
              style={{
                backgroundColor: '#0c2445',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                boxShadow: 'inset 0 2px 4px rgba(0, 0, 0, 0.3)'
              }}
            >
              <User className="w-5 h-5 text-[#93c5fd]/80 flex-shrink-0" />
              <input
                type="text"
                id="login-username-input"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                className="w-full bg-transparent border-none outline-none text-[#f8fafc] text-sm placeholder-[#93c5fd]/50 font-sans"
              />
            </div>

            {/* Password Input Field */}
            <div 
              className="flex items-center gap-3.5 px-4 py-3 rounded-lg transition-all focus-within:ring-1 focus-within:ring-[#38bdf8]"
              style={{
                backgroundColor: '#0c2445',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                boxShadow: 'inset 0 2px 4px rgba(0, 0, 0, 0.3)'
              }}
            >
              <Lock className="w-5 h-5 text-[#93c5fd]/80 flex-shrink-0" />
              <input
                type={showPassword ? 'text' : 'password'}
                id="login-password-input"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-transparent border-none outline-none text-[#f8fafc] text-sm placeholder-[#93c5fd]/50 font-sans tracking-wider"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="text-[#93c5fd]/60 hover:text-[#38bdf8] transition"
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {/* Remember Me & Forgot Password (matching typography & placement from image) */}
            <div className="flex items-center justify-between text-xs pt-1 pb-2">
              {/* Custom Checkbox */}
              <label className="flex items-center gap-2 cursor-pointer text-[#bae6fd] select-none hover:text-white transition">
                <div 
                  onClick={() => setRememberMe(!rememberMe)}
                  className={`w-4 h-4 rounded flex items-center justify-center transition-all ${
                    rememberMe 
                      ? 'bg-[#38bdf8] text-[#08172e] shadow-[0_0_8px_rgba(56,189,248,0.6)]' 
                      : 'bg-[#081e3a] border border-[#38bdf8]/40'
                  }`}
                >
                  {rememberMe && <Check className="w-3 h-3 stroke-[3]" />}
                </div>
                <span className="text-[13px] font-normal text-[#dbeafe]">Remember me</span>
              </label>

              {/* Forgot Password? in italic font */}
              <button
                type="button"
                id="login-forgot-btn"
                onClick={() => {
                  setIsForgotOpen(true);
                  setForgotSent(false);
                }}
                className="text-[13px] text-[#7dd3fc] italic hover:text-[#38bdf8] hover:underline transition cursor-pointer"
              >
                Forgot Password?
              </button>
            </div>

            {/* Solid Deep Blue LOGIN Button (matching image) */}
            <button
              type="submit"
              id="login-submit-btn"
              className="w-full py-3.5 rounded-lg text-white font-bold text-sm tracking-widest uppercase transition-all duration-200 cursor-pointer shadow-lg active:scale-[0.99] flex items-center justify-center gap-2"
              style={{
                background: 'linear-gradient(180deg, #0284c7 0%, #0369a1 100%)',
                border: '1px solid rgba(56, 189, 248, 0.4)',
                boxShadow: '0 8px 20px rgba(2, 132, 199, 0.35), inset 0 1px 1px rgba(255, 255, 255, 0.3)'
              }}
            >
              <span>LOGIN</span>
            </button>

            {/* Secondary Google Sign-In */}
            <div className="pt-2">
              <button
                type="button"
                id="login-google-btn"
                onClick={handleGoogleSignIn}
                className="w-full py-2.5 rounded-lg bg-[#081e3a]/60 hover:bg-[#0c2a52] border border-[#38bdf8]/20 text-[#bae6fd] text-xs font-medium transition flex items-center justify-center gap-2 cursor-pointer"
              >
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.33 24 12 24z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 9.98 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
                  />
                </svg>
                <span>Sign in with Google</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Forgot Password Modal */}
      {isForgotOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
          <div 
            className="w-full max-w-sm rounded-2xl p-6 text-xs text-[#f8fafc] space-y-4 shadow-2xl"
            style={{
              background: '#0c2445',
              border: '1.5px solid #38bdf8',
              boxShadow: '0 0 30px rgba(56, 189, 248, 0.3)'
            }}
          >
            <div className="flex items-center justify-between border-b border-[#38bdf8]/30 pb-3">
              <span className="font-semibold text-sm text-[#e0f2fe]">Reset Password</span>
              <button 
                onClick={() => setIsForgotOpen(false)}
                className="text-[#94a3b8] hover:text-white text-base font-bold"
              >
                ✕
              </button>
            </div>

            {forgotSent ? (
              <div className="space-y-3 text-center py-2">
                <div className="w-10 h-10 rounded-full bg-[#22c55e]/20 border border-[#22c55e]/50 flex items-center justify-center mx-auto text-[#22c55e]">
                  ✓
                </div>
                <p className="text-sm font-medium text-[#f8fafc]">Instructions Sent</p>
                <p className="text-[#94a3b8]">Recovery link dispatched to {username}.</p>
                <button
                  onClick={() => setIsForgotOpen(false)}
                  className="w-full py-2 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white font-medium transition"
                >
                  Back to Login
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-[#94a3b8]">Enter your corporate email address to receive password reset instructions.</p>
                <input
                  type="email"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin@cybershield.sec"
                  className="w-full bg-[#08172e] border border-[#38bdf8]/40 rounded-lg px-3 py-2 text-[#f8fafc] outline-none"
                />
                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    onClick={() => setIsForgotOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-[#94a3b8] hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => setForgotSent(true)}
                    className="px-4 py-1.5 rounded-lg bg-[#0284c7] hover:bg-[#0369a1] text-white font-medium flex items-center gap-1.5"
                  >
                    <span>Send Link</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
