import { useState } from "react";
import type { Page, Viewer } from "./App";
import Brand from "./Brand";
import SignalField from "./SignalField";
import { Icon } from "./Dashboard";

export default function AuthPage({
  mode,
  navigate,
  onComplete,
}: {
  mode: "signin" | "signup";
  navigate: (page: Page) => void;
  onComplete: (viewer: Viewer) => void;
}) {
  const signup = mode === "signup";
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  function submit(event: React.FormEvent) {
    event.preventDefault();
    onComplete({
      name: name.trim() || email.split("@")[0].replace(/[._-]/g, " ") || "Analyst",
      email: email.trim(),
    });
    setPassword("");
  }

  return (
    <div className="auth-page">
      <header className="auth-header">
        <Brand onClick={() => navigate("home")} />
        <button className="auth-back" onClick={() => navigate("home")}>
          <Icon name="arrow" size={15} />
          Back to home
        </button>
      </header>
      <main className="auth-layout">
        <section className="auth-story">
          <SignalField />
          <div className="auth-story-content">
            <div className="red-eyebrow">
              <span />
              YOUR NEXT LAYER OF DEFENSE
            </div>
            <h2>
              On the right side
              <br />
              of every <span>link.</span>
            </h2>
            <p>
              Good instincts deserve a safer workspace.
              <br />
              Take a closer look, without getting too close.
            </p>
          </div>
          <span className="auth-story-footer">PHISH&CHIPS / CURIOSITY, CONTAINED.</span>
        </section>
        <section className="auth-form-panel">
          <div className="auth-form-wrap">
            <div className="red-eyebrow">
              <span />
              {signup ? "CREATE YOUR WORKSPACE" : "WELCOME TO YOUR WORKSPACE"}
            </div>
            <h1>{signup ? "A safer space\nstarts here." : "Welcome back."}</h1>
            <p className="auth-subtitle">
              {signup
                ? "A little curiosity. A lot of protection."
                : "Your next investigation is waiting."}
            </p>
            <form onSubmit={submit}>
              {signup && (
                <label className="auth-field">
                  Full name
                  <input
                    autoComplete="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Your full name"
                    required
                    minLength={2}
                    maxLength={80}
                  />
                </label>
              )}
              <label className="auth-field">
                Email address
                <input
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  required
                  maxLength={180}
                />
              </label>
              <label className="auth-field">
                Password
                <div className="password-input">
                  <input
                    type={showPassword ? "text" : "password"}
                    autoComplete={signup ? "new-password" : "current-password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 8 characters"
                    required
                    minLength={8}
                    maxLength={128}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </label>
              <button className="red-button auth-submit" type="submit">
                {signup ? "Create workspace" : "Sign in"}
                <Icon name="arrow" size={18} />
              </button>

              <div style={{ margin: "16px 0 10px", textAlign: "center" }}>
                <span style={{ color: "#a59995", fontSize: "11px", letterSpacing: "0.05em" }}>
                  — OR QUICK DEMO —
                </span>
              </div>
              <button
                type="button"
                className="outline-button auth-demo-btn"
                style={{
                  width: "100%",
                  justifyContent: "center",
                  gap: "8px",
                  padding: "12px",
                  border: "1px dashed #d5352b",
                  color: "#f2eeed",
                  background: "rgba(213, 53, 43, 0.08)",
                  cursor: "pointer",
                  fontFamily: "var(--mono)",
                  fontSize: "12px",
                }}
                onClick={() => {
                  onComplete({
                    name: "SecOps Lead Analyst",
                    email: "analyst@phishchips.internal",
                  });
                }}
              >
                <Icon name="shield" size={15} />
                Instant Demo Access (Lead Analyst)
              </button>
            </form>
            <p className="auth-switch">
              {signup ? "Already have a workspace?" : "New to Phish&Chips?"}
              <button onClick={() => navigate(signup ? "signin" : "signup")}>
                {signup ? "Sign in" : "Create a workspace"}
              </button>
            </p>
          </div>
        </section>
      </main>
      <footer className="auth-footer">
        <span>© {new Date().getFullYear()} Phish&Chips.</span>
      </footer>
    </div>
  );
}
