import { useEffect, useState } from "react";
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
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [googleClientId, setGoogleClientId] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    fetch("/api/config")
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg) => {
        if (!mounted || !cfg?.google_client_id) return;
        setGoogleClientId(cfg.google_client_id);
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!googleClientId) return;

    function renderGoogleBtn() {
      if (window.google?.accounts?.id) {
        window.google.accounts.id.initialize({
          client_id: googleClientId,
          callback: async (response: any) => {
            if (!response?.credential) return;
            setSubmitting(true);
            try {
              const res = await fetch("/api/auth/google", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ credential: response.credential }),
              });
              if (res.ok) {
                const data = await res.json();
                if (data?.user) {
                  onComplete({
                    name: data.user.name || "Google Analyst",
                    email: data.user.email,
                  });
                  return;
                }
              }
            } catch (err) {
              console.error("Google authentication error:", err);
            } finally {
              setSubmitting(false);
            }
          },
        });

        const target = document.getElementById("google-signin-target");
        if (target) {
          target.innerHTML = "";
          window.google.accounts.id.renderButton(target, {
            theme: "filled_black",
            size: "large",
            text: signup ? "signup_with" : "signin_with",
            shape: "rectangular",
            width: 320,
          });
        }
      }
    }

    if (window.google?.accounts?.id) {
      renderGoogleBtn();
    } else {
      const timer = setInterval(() => {
        if (window.google?.accounts?.id) {
          clearInterval(timer);
          renderGoogleBtn();
        }
      }, 200);
      return () => clearInterval(timer);
    }
  }, [googleClientId, signup, onComplete]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    const resolvedName = name.trim();
    const resolvedEmail = email.trim().toLowerCase();

    const endpoint = signup ? "/api/auth/register" : "/api/auth/login";
    const body = signup
      ? { email: resolvedEmail, password, name: resolvedName }
      : { email: resolvedEmail, password };

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data?.detail || "Authentication failed. Please verify your details.");
        setSubmitting(false);
        return;
      }
      if (data?.user) {
        onComplete({ name: data.user.name, email: data.user.email });
        setPassword("");
        setSubmitting(false);
        return;
      }
    } catch {
      setError("Unable to connect to authentication server. Please retry.");
    }
    setSubmitting(false);
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
            {googleClientId && (
              <div style={{ marginBottom: "20px" }}>
                <div
                  id="google-signin-target"
                  style={{
                    display: "flex",
                    justifyContent: "center",
                    minHeight: "44px",
                  }}
                />
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    margin: "18px 0 10px",
                  }}
                >
                  <div style={{ flex: 1, height: "1px", background: "rgba(255, 255, 255, 0.08)" }} />
                  <span style={{ color: "#a59995", fontSize: "11px", letterSpacing: "0.06em", fontFamily: "var(--mono)" }}>
                    OR CONTINUE WITH EMAIL
                  </span>
                  <div style={{ flex: 1, height: "1px", background: "rgba(255, 255, 255, 0.08)" }} />
                </div>
              </div>
            )}
            <form onSubmit={submit}>
              {error && (
                <div
                  style={{
                    margin: "0 0 16px 0",
                    padding: "10px 14px",
                    background: "rgba(213, 53, 43, 0.12)",
                    border: "1px solid rgba(213, 53, 43, 0.35)",
                    borderRadius: "6px",
                    color: "#f87171",
                    fontSize: "12px",
                    fontFamily: "var(--mono)",
                    lineHeight: 1.4,
                  }}
                >
                  {error}
                </div>
              )}
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
              <button className="red-button auth-submit" type="submit" disabled={submitting}>
                {submitting ? "Authenticating..." : signup ? "Create workspace" : "Sign in"}
                <Icon name="arrow" size={18} />
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
