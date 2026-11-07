import { useState } from "react";
import type { Page } from "./App";
import Brand from "./Brand";
import SignalField from "./SignalField";
import { Icon } from "./Dashboard";

const benefits = [
  {
    number: "01",
    icon: "lock" as const,
    title: "Keep the threat out.",
    copy: "A dedicated, isolated environment keeps suspicious links on the other side of your network.",
  },
  {
    number: "02",
    icon: "activity" as const,
    title: "See beyond the URL.",
    copy: "Understand the behavior behind a link, from credential harvesting to brand impersonation.",
  },
  {
    number: "03",
    icon: "shield" as const,
    title: "Trade doubt for clarity.",
    copy: "Get a clear verdict, confidence score, and investigation trail. All in one focused workspace.",
  },
];

export default function Landing({
  navigate,
  hasViewer,
}: {
  navigate: (page: Page) => void;
  hasViewer: boolean;
}) {
  const [menu, setMenu] = useState(false);
  const [faq, setFaq] = useState<number | null>(0);
  function scrollTo(id: string) {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
    setMenu(false);
  }
  return (
    <div className="landing-page">
      <header className="site-header">
        <Brand onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })} />
        <nav
          id="landing-navigation"
          className={`site-navigation ${menu ? "menu-open" : ""}`}
          aria-label="Landing navigation"
        >
          <button
            className="current"
            onClick={() => {
              window.scrollTo({ top: 0, behavior: "smooth" });
              setMenu(false);
            }}
          >
            Home
          </button>
          <button onClick={() => scrollTo("platform")}>
            Platform
            <Icon name="chevron" size={13} />
          </button>
          <button onClick={() => scrollTo("how-it-works")}>How it works</button>
          <button onClick={() => scrollTo("questions")}>FAQs</button>
        </nav>
        <div className="site-header-actions">
          <button
            className="site-signin"
            onClick={() => navigate(hasViewer ? "dashboard" : "signin")}
          >
            {hasViewer ? "Dashboard" : "Sign in"}
          </button>
          <button
            className="red-button header-start"
            onClick={() => navigate(hasViewer ? "dashboard" : "signup")}
          >
            {hasViewer ? "Open dashboard" : "Get started"}
            <Icon name="arrow" size={17} />
          </button>
          <button
            className="mobile-menu"
            aria-label={menu ? "Close navigation" : "Open navigation"}
            aria-expanded={menu}
            aria-controls="landing-navigation"
            onClick={() => setMenu(!menu)}
          >
            <span />
            <span className={menu ? "menu-line-open" : ""} />
          </button>
        </div>
      </header>

      <main className="landing-main">
        <section className="landing-hero">
          <SignalField />
          <div className="landing-hero-content">
            <div className="red-eyebrow">
              <span />
              CURIOSITY, WITHOUT COMPROMISE
            </div>
            <h1>
              Trust your instincts.
              <br />
              Not every <span>link.</span>
            </h1>
            <p>
              A suspicious link shouldn’t be a leap of faith.
              <br className="wide-only" /> Investigate phishing and malware in an isolated
              <br className="wide-only" /> workspace. Leave the risk outside.
            </p>
            <div className="hero-actions">
              <button
                className="red-button"
                onClick={() => navigate(hasViewer ? "dashboard" : "signup")}
              >
                {hasViewer ? "Open your dashboard" : "Secure your curiosity"}
                <Icon name="arrow" size={19} />
              </button>
              <button className="text-button" onClick={() => scrollTo("how-it-works")}>
                <span className="play-symbol">
                  <svg
                    width="10"
                    height="10"
                    viewBox="0 0 10 10"
                    fill="currentColor"
                    aria-hidden="true"
                  >
                    <path d="m3 1 6 4-6 4V1Z" />
                  </svg>
                </span>
                See how it works
              </button>
            </div>
            <div className="hero-reassurance">
              <Icon name="shield" size={13} />
              <span>No downloads. No host exposure. No second guessing.</span>
            </div>
          </div>
          <div className="hero-sequence">
            {["Isolate the link", "Observe the behavior", "Know the verdict"].map(
              (label, index) => (
                <div key={label}>
                  <span>
                    0{index + 1}
                    <span className="sequence-slash"> / </span>
                  </span>
                  <p>{label}</p>
                </div>
              ),
            )}
          </div>
          <div className="hero-bottom-line">
            <span>BUILT FOR ANALYSTS. OPEN TO THE CURIOUS.</span>
            <button onClick={() => scrollTo("platform")}>
              SCROLL TO EXPLORE
              <Icon name="arrow" size={14} />
            </button>
          </div>
        </section>

        <section className="landing-benefits landing-section" id="platform">
          <div className="section-intro">
            <div className="red-eyebrow">
              <span />
              THE PLATFORM
            </div>
            <div>
              <h2>
                Open questions.
                <br />
                <span>Closed environments.</span>
              </h2>
              <p>
                Everything you need to look closer.
                <br />
                Nothing that puts your network at risk.
              </p>
            </div>
          </div>
          <div className="benefit-grid">
            {benefits.map((item) => (
              <article key={item.number}>
                <div className="benefit-top">
                  <Icon name={item.icon} size={25} />
                  <span>/{item.number}</span>
                </div>
                <h3>{item.title}</h3>
                <p>{item.copy}</p>
                <span className="benefit-corner" />
              </article>
            ))}
          </div>
        </section>

        <section className="landing-process landing-section" id="how-it-works">
          <div className="red-eyebrow">
            <span />
            FROM SUSPICION TO CERTAINTY
          </div>
          <div className="process-layout">
            <div>
              <h2>
                One link.
                <br />
                Four layers of
                <br />
                <span>peace of mind.</span>
              </h2>
              <p>
                Behind a simple command bar is a carefully
                <br className="wide-only" /> contained investigation. Here’s the blueprint.
              </p>
              <button
                className="text-button red-link"
                onClick={() => navigate(hasViewer ? "dashboard" : "signup")}
              >
                Explore the workspace
                <Icon name="arrow" size={17} />
              </button>
            </div>
            <ol>
              {[
                {
                  title: "Dispatch",
                  text: "Submit a suspicious URL without opening it on your device.",
                },
                {
                  title: "Isolate",
                  text: "Separate the investigation from your host with a network cage.",
                },
                {
                  title: "Observe",
                  text: "Examine the target inside an ephemeral execution environment.",
                },
                {
                  title: "Understand",
                  text: "Read the verdict, confidence score, and threat classification.",
                },
              ].map((step, i) => (
                <li key={step.title}>
                  <span className="process-number">0{i + 1}</span>
                  <div>
                    <h3>{step.title}</h3>
                    <p>{step.text}</p>
                  </div>
                  <Icon name={i === 3 ? "check" : "arrow"} size={18} />
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="landing-faq landing-section" id="questions">
          <div>
            <div className="red-eyebrow">
              <span />
              GOOD QUESTIONS
            </div>
            <h2>
              A little more
              <br />
              <span>clarity.</span>
            </h2>
          </div>
          <div className="faq-list">
            {[
              {
                q: "What is Phish&Chips?",
                a: "A focused investigation workspace for exploring suspicious URLs, threat verdicts, and isolation workflows.",
              },
              {
                q: "What can I investigate?",
                a: "Explore suspicious links, credential harvesting patterns, and brand impersonation from a single workspace.",
              },
              {
                q: "What does an investigation include?",
                a: "Each record brings together a target URL, threat classification, confidence score, network isolation status, and a clear verdict.",
              },
            ].map((item, i) => (
              <div className="faq-item" key={item.q}>
                <button
                  aria-expanded={faq === i}
                  aria-controls={`faq-answer-${i}`}
                  onClick={() => setFaq(faq === i ? null : i)}
                >
                  {item.q}
                  <span>{faq === i ? "−" : "+"}</span>
                </button>
                <div id={`faq-answer-${i}`} hidden={faq !== i}>
                  <p>{item.a}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
        <section className="landing-cta">
          <div className="red-eyebrow">
            <span />
            STAY ON THE RIGHT SIDE OF THE LINK
          </div>
          <h2>
            Stay curious.
            <br />
            <span>Stay uncompromised.</span>
          </h2>
          <button
            className="red-button"
            onClick={() => navigate(hasViewer ? "dashboard" : "signup")}
          >
            {hasViewer ? "Back to your dashboard" : "Enter a safer workspace"}
            <Icon name="arrow" size={19} />
          </button>
        </section>
      </main>
      <footer className="site-footer">
        <Brand onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })} />
        <span>© {new Date().getFullYear()} Phish&Chips. Curiosity, contained.</span>
        <button onClick={() => navigate(hasViewer ? "dashboard" : "signin")}>
          {hasViewer ? "Dashboard" : "Sign in"}
          <Icon name="arrow" size={14} />
        </button>
      </footer>
    </div>
  );
}
