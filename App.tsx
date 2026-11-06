import React, { useState } from "react";
import { motion } from "motion/react";
import { Circle, Chrome, Github, Eye, EyeOff } from "lucide-react";

export default function App() {
  const [showPassword, setShowPassword] = useState(false);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    window.location.href = "/console";
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15,
        delayChildren: 0.2,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.5, ease: "easeOut" },
    },
  };

  return (
    <div className="bg-black min-h-screen text-white flex items-center justify-center p-0 lg:p-6 overflow-hidden selection:bg-white selection:text-black">
      {/* Container Card */}
      <div className="relative w-full max-w-7xl h-full lg:h-[92vh] bg-black rounded-none lg:rounded-[32px] border-0 lg:border border-white/10 flex flex-col lg:flex-row overflow-hidden lg:p-4">
        {/* Left Column: Hero & Background Video */}
        <div className="relative hidden lg:flex w-[52%] flex-col items-center justify-end pb-32 px-12 rounded-3xl overflow-hidden shadow-2xl h-full">
          {/* Background Video (NO overlays or masks) */}
          <video
            className="absolute inset-0 w-full h-full object-cover"
            autoPlay
            muted
            loop
            playsInline
          >
            <source
              src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260506_081238_406ed0e3-5d83-436e-a512-0bbff7ec5b95.mp4"
              type="video/mp4"
            />
          </video>

          {/* Hero Content Container */}
          <motion.div
            className="z-10 w-full max-w-xs space-y-8 text-center"
            variants={containerVariants}
            initial="hidden"
            animate="visible"
          >
            {/* Brand / Logo */}
            <motion.div
              variants={itemVariants}
              className="flex items-center justify-center gap-2.5"
            >
              <Circle className="w-5 h-5 fill-white text-white" />
              <span className="text-xl font-semibold tracking-tight text-white">
                Aurora
              </span>
            </motion.div>

            {/* Heading Block */}
            <motion.div variants={itemVariants} className="space-y-2">
              <h2 className="text-4xl font-medium tracking-tight whitespace-nowrap text-white">
                Join Aurora
              </h2>
              <p className="text-white/60 text-sm leading-relaxed px-4">
                Follow these 3 quick phases to activate your space.
              </p>
            </motion.div>

            {/* Steps */}
            <motion.div variants={itemVariants} className="space-y-3 pt-2 text-left">
              <StepItem number="1" text="Register your identity" active={true} />
              <StepItem number="2" text="Configure your studio" active={false} />
              <StepItem number="3" text="Finalize your profile" active={false} />
            </motion.div>
          </motion.div>
        </div>

        {/* Right Column: Sign Up Form */}
        <div className="flex-1 flex flex-col items-center justify-center py-12 lg:py-6 px-4 sm:px-12 lg:px-16 xl:px-24 overflow-y-auto lg:overflow-hidden">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8, ease: "easeOut" }}
            className="w-full max-w-xl space-y-8 lg:space-y-6 sm:space-y-10"
          >
            {/* Header */}
            <div className="space-y-2">
              <h1 className="text-3xl font-medium tracking-tight text-white">
                Create New Profile
              </h1>
              <p className="text-white/40 text-sm">
                Input your basic details to begin the journey.
              </p>
            </div>

            {/* Social Buttons */}
            <div className="grid grid-cols-2 gap-4">
              <SocialButton
                icon={<Chrome className="w-4 h-4 text-white" />}
                label="Google"
                onClick={() => {
                  window.location.href = "/console";
                }}
              />
              <SocialButton
                icon={<Github className="w-4 h-4 text-white" />}
                label="GitHub"
                onClick={() => {
                  window.location.href = "/console";
                }}
              />
            </div>

            {/* Divider */}
            <div className="relative flex items-center justify-center">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-white/10" />
              </div>
              <span className="relative bg-black px-4 text-xs font-medium text-white/40 uppercase tracking-widest">
                Or
              </span>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <InputGroup
                  label="First Name"
                  placeholder="Ada"
                  type="text"
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                />
                <InputGroup
                  label="Last Name"
                  placeholder="Lovelace"
                  type="text"
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                />
              </div>

              <InputGroup
                label="Email"
                placeholder="ada@lovelace.io"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />

              {/* Password Group with Eye Toggle */}
              <div className="space-y-1.5 text-left">
                <label className="text-sm font-medium text-white block">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="w-full bg-brand-gray border-none rounded-xl h-11 px-4 pr-11 text-white placeholder:text-white/20 focus:ring-2 focus:ring-white/20 transition-all outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white transition-colors p-1"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
                <p className="text-[11px] text-white/40">
                  Requires at least 8 symbols.
                </p>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                className="w-full h-14 bg-white text-black font-semibold rounded-xl hover:bg-white/90 active:scale-[0.98] transition-all duration-200 mt-4 shadow-lg cursor-pointer flex items-center justify-center gap-2"
              >
                Create Account
              </button>
            </form>

            {/* Footer Link */}
            <div className="text-center pt-2">
              <a
                href="/console"
                className="text-xs text-white/40 hover:text-white transition-colors"
              >
                Member of the team? <span className="text-white underline underline-offset-4">Log in</span>
              </a>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------
// Reusable Components
// ----------------------------------------------------

interface StepItemProps {
  number: string;
  text: string;
  active?: boolean;
}

export function StepItem({ number, text, active = false }: StepItemProps) {
  return (
    <div
      className={`flex items-center gap-3.5 p-3 rounded-2xl transition-all duration-300 ${
        active
          ? "bg-white text-black border border-white shadow-md"
          : "bg-brand-gray text-white border-none"
      }`}
    >
      <div
        className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold shrink-0 ${
          active ? "bg-black text-white" : "bg-white/10 text-white/40"
        }`}
      >
        {number}
      </div>
      <span className="text-xs font-medium tracking-tight truncate">{text}</span>
    </div>
  );
}

interface SocialButtonProps {
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
}

export function SocialButton({ icon, label, onClick }: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center justify-center gap-2.5 h-11 bg-black border border-white/10 rounded-xl hover:bg-white/5 transition-all text-xs font-medium text-white cursor-pointer active:scale-[0.98]"
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

interface InputGroupProps {
  label: string;
  placeholder: string;
  type: string;
  value?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

export function InputGroup({
  label,
  placeholder,
  type,
  value,
  onChange,
}: InputGroupProps) {
  return (
    <div className="space-y-1.5 text-left">
      <label className="text-sm font-medium text-white block">{label}</label>
      <input
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        required
        className="w-full bg-brand-gray border-none rounded-xl h-11 px-4 text-white placeholder:text-white/20 focus:ring-2 focus:ring-white/20 transition-all outline-none"
      />
    </div>
  );
}
