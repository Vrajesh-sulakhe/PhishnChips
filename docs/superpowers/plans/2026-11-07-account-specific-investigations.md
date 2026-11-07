# Account-Specific Investigations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scope all recent investigations in Phish&Chips strictly to the authenticated user account so analysts only see detonations initiated in their own workspace.

**Architecture:** 
1. Backend: Update `/api/scans/recent` to extract the session token from the cookie or `Authorization: Bearer <token>` header, query the SQLite database via `db.get_user_scans(user_id)`, and return an empty list if unauthenticated. Update `save_scan()`'s `ON CONFLICT` clause in SQLite to ensure `user_id` is never overwritten.
2. Frontend: Remove static mock records from `Dashboard.tsx` (`initialRecords = []`), update `loadRecentScans()` to fetch account-scoped scans with credentials and update state cleanly, and provide an account-specific empty state.
3. Auth Token Propagation: Ensure `src/App.tsx` and `src/AuthPage.tsx` preserve the session token in `sessionStorage` so API requests (`/api/scans/recent`, `/api/scan`) reliably authenticate.

**Tech Stack:** Python 3.12/3.14 (FastAPI, SQLite 3 WAL), React 19 / TypeScript, Vite.

---

## Global Constraints
- Target URL: `https://139.84.159.12.sslip.io`
- Zero data leakage across user workspaces: User A must never see User B's scans.
- All existing 50 pytest tests must pass without regressions.
- Every change must be verified locally and deployed to the Vultr VM via `deploy.sh`.

---

## Tasks

### Task 1: Backend Isolation & Database Hardening
**Files:**
- Modify: `backend/db.py`
- Modify: `backend/main.py`
- Test: `backend/tests/test_api.py`

- [ ] **Step 1: Write tests for account-scoped scan retrieval**
  In `backend/tests/test_api.py`, add `test_account_specific_scans()` creating two distinct users, adding scans with each `user_id`, and verifying `/api/scans/recent` only returns User A's scans for User A, User B's scans for User B, and an empty list for anonymous requests.
- [ ] **Step 2: Run test to verify failure**
  Run: `./.venv/bin/pytest backend/tests/test_api.py -k test_account_specific_scans`
- [ ] **Step 3: Update `backend/db.py` and `backend/main.py`**
  - In `backend/db.py` (`save_scan`): Add `user_id = COALESCE(excluded.user_id, scans.user_id)` to `ON CONFLICT(job_id) DO UPDATE SET`.
  - In `backend/main.py` (`get_recent_scans`): Extract current user optional; if found, return `db.get_user_scans(user["id"], limit=25)`; else return `[]`.
- [ ] **Step 4: Run test to verify it passes**
  Run: `./.venv/bin/pytest backend/tests/test_api.py`
- [ ] **Step 5: Run full test suite**
  Run: `./.venv/bin/pytest backend/tests/`

### Task 2: Frontend Dashboard State & Token Propagation
**Files:**
- Modify: `src/App.tsx`
- Modify: `src/AuthPage.tsx`
- Modify: `src/Dashboard.tsx`

- [ ] **Step 1: Save session token on login/registration**
  In `src/AuthPage.tsx` and `src/App.tsx`, save `data.token` to `window.sessionStorage.setItem("phishchips_token", data.token)` when authenticated.
- [ ] **Step 2: Update `src/Dashboard.tsx` to clear mock records and use account data**
  - Change `initialRecords` in `Dashboard.tsx` to `[]`.
  - In `loadRecentScans()`, ensure `fetch("/api/scans/recent", { credentials: "same-origin", headers: ... })` sets `records` to `mapped` (or `[]` if none).
  - In `empty-state`, distinguish between "No investigations in your workspace yet" vs "No matching records found for search filter".
  - In `startScan()`, include credentials and token header so scans are attributed to the logged-in user.
- [ ] **Step 3: Build frontend**
  Run: `npm run build`

### Task 3: Production Deployment & Remote Multi-Tenant Verification
**Files:**
- Deploy via `deploy.sh` to Vultr VM `139.84.159.12`

- [ ] **Step 1: Execute 1-click deployment**
  Run: `bash deploy.sh`
- [ ] **Step 2: Verify live endpoints on Vultr VM**
  Run remote test creating two sessions and proving `/api/scans/recent` returns strictly isolated results.

