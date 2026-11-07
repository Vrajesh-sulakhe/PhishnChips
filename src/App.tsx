import { useEffect, useState } from "react";
import Dashboard from "./Dashboard";
import Landing from "./Landing";
import AuthPage from "./AuthPage";

export type Page = "home" | "signin" | "signup" | "dashboard";
export type Viewer = { name: string; email: string };

const viewerSessionKey = "phish-and-chips.viewer";

function pageFromLocation(): Page {
  const hash = window.location.hash.slice(1).split("?")[0];
  if (hash === "signin" || hash === "signup" || hash === "dashboard") return hash;
  const path = window.location.pathname.replace(/^\/+/, "").split("/")[0];
  if (path === "signin" || path === "login") return "signin";
  if (path === "signup") return "signup";
  if (path === "dashboard" || path === "console" || path === "product") return "dashboard";
  return "home";
}

function readViewerSession(): Viewer | null {
  try {
    const stored = window.sessionStorage.getItem(viewerSessionKey);
    if (stored) {
      const identity = JSON.parse(stored);
      if (
        typeof identity?.name === "string" &&
        identity.name.trim() &&
        typeof identity?.email === "string" &&
        identity.email.includes("@")
      ) {
        return { name: identity.name, email: identity.email };
      }
    }
  } catch {
    // A missing or unavailable browser session must not break navigation.
  }
  // Provide analyst session when direct dashboard/console/product path was opened
  const path = window.location.pathname.replace(/^\/+/, "").split("/")[0];
  const hash = window.location.hash.slice(1).split("?")[0];
  if (path === "dashboard" || path === "console" || path === "product" || hash === "dashboard") {
    return { name: "SecOps Lead Analyst", email: "analyst@phishchips.internal" };
  }
  return null;
}

function writeViewerSession(viewer: Viewer | null) {
  try {
    if (viewer) window.sessionStorage.setItem(viewerSessionKey, JSON.stringify(viewer));
    else window.sessionStorage.removeItem(viewerSessionKey);
  } catch {
    // Keep the in-memory flow usable when browser storage is unavailable.
  }
}

export default function App() {
  const [page, setPage] = useState<Page>(pageFromLocation);
  const [viewer, setViewer] = useState<Viewer | null>(readViewerSession);

  useEffect(() => {
    const change = () => {
      setPage(pageFromLocation());
      window.scrollTo({ top: 0 });
    };
    window.addEventListener("hashchange", change);
    window.addEventListener("popstate", change);
    return () => {
      window.removeEventListener("hashchange", change);
      window.removeEventListener("popstate", change);
    };
  }, []);

  useEffect(() => {
    document.title = `${page === "home" ? "Stay curious. Stay protected." : page === "dashboard" && viewer ? "Dashboard" : page === "signup" ? "Create your workspace" : "Sign in"} — Phish&Chips`;
  }, [page, viewer]);

  function navigate(next: Page) {
    window.location.hash = next === "home" ? "" : next;
    setPage(next);
    window.scrollTo({ top: 0 });
  }

  if (page === "home") return <Landing navigate={navigate} hasViewer={!!viewer} />;

  if (page === "dashboard") {
    const currentViewer = viewer || { name: "SecOps Lead Analyst", email: "analyst@phishchips.internal" };
    return (
      <Dashboard
        viewer={currentViewer}
        onHome={() => navigate("home")}
        onSignOut={() => {
          writeViewerSession(null);
          setViewer(null);
          navigate("home");
        }}
      />
    );
  }

  return (
    <AuthPage
      key={page}
      mode={page === "signup" ? "signup" : "signin"}
      navigate={navigate}
      onComplete={(identity) => {
        writeViewerSession(identity);
        setViewer(identity);
        navigate("dashboard");
      }}
    />
  );
}
