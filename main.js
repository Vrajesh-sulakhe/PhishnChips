/**
 * main.js - Intelligence Designed To Evolve
 * Single-viewport landing page interactions, metric count-up engine,
 * mobile sheet drawer, and Aurora Sign Up modal controller.
 */

document.addEventListener('DOMContentLoaded', () => {
  // ----------------------------------------------------
  // 1. STATS COUNT-UP ANIMATION ENGINE
  // ----------------------------------------------------
  const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

  const animateCountUp = (element, target, duration, decimals, suffix, delay) => {
    setTimeout(() => {
      const startTime = performance.now();
      const startVal = 0;

      const updateCounter = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easedProgress = easeOutCubic(progress);
        const currentVal = startVal + (target - startVal) * easedProgress;

        if (decimals > 0) {
          element.textContent = currentVal.toFixed(decimals) + suffix;
        } else {
          element.textContent = Math.round(currentVal) + suffix;
        }

        if (progress < 1) {
          requestAnimationFrame(updateCounter);
        } else {
          // Final exact value
          element.textContent = (decimals > 0 ? target.toFixed(decimals) : Math.round(target)) + suffix;
        }
      };

      requestAnimationFrame(updateCounter);
    }, delay);
  };

  const initStatsCountUp = () => {
    const statItems = document.querySelectorAll('.stat-item');
    if (!statItems.length) return;

    let animated = false;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && !animated) {
            animated = true;
            observer.disconnect();

            statItems.forEach((item, index) => {
              const target = parseFloat(item.getAttribute('data-target') || '0');
              const decimals = parseInt(item.getAttribute('data-decimals') || '0', 10);
              const suffix = item.getAttribute('data-suffix') || '';
              const valueEl = item.querySelector('.stat-value');

              if (!valueEl) return;

              // Specifications:
              // Duration: 1500 + i * 80 ms
              // Start offset / delay: 480 + i * 90 ms
              const duration = 1500 + index * 80;
              const delay = 480 + index * 90;

              animateCountUp(valueEl, target, duration, decimals, suffix, delay);
            });
          }
        });
      },
      { threshold: 0.25 }
    );

    const statsFooter = document.getElementById('statsFooter');
    if (statsFooter) {
      observer.observe(statsFooter);
    } else {
      statItems.forEach((item) => observer.observe(item));
    }
  };

  initStatsCountUp();

  // ----------------------------------------------------
  // 2. DESKTOP & MOBILE NAVIGATION
  // ----------------------------------------------------
  const navLinks = document.querySelectorAll('.nav-link, .mobile-nav-link');
  navLinks.forEach((link) => {
    link.addEventListener('click', (e) => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('#')) {
        e.preventDefault();
        // Update active class
        navLinks.forEach((l) => l.classList.remove('active'));
        document.querySelectorAll(`[href="${href}"]`).forEach((l) => l.classList.add('active'));

        // If user clicked #product, navigate to live console
        if (href === '#product') {
          window.location.href = '/console';
        }
      }
    });
  });

  // ----------------------------------------------------
  // 3. MOBILE BURGER MENU (<= 720px)
  // ----------------------------------------------------
  const burgerBtn = document.getElementById('mobileBurgerBtn');
  const menuOverlay = document.getElementById('mobileMenuOverlay');
  const menuSheet = document.getElementById('mobileMenuSheet');

  const openMobileMenu = () => {
    if (!burgerBtn || !menuOverlay || !menuSheet) return;
    burgerBtn.classList.add('is-open');
    burgerBtn.setAttribute('aria-expanded', 'true');
    menuOverlay.hidden = false;
    menuSheet.hidden = false;
    // Force reflow for CSS transitions
    void menuOverlay.offsetWidth;
    void menuSheet.offsetWidth;
    menuOverlay.classList.add('active');
    menuSheet.classList.add('active');
    document.body.classList.add('menu-open');
  };

  const closeMobileMenu = () => {
    if (!burgerBtn || !menuOverlay || !menuSheet) return;
    burgerBtn.classList.remove('is-open');
    burgerBtn.setAttribute('aria-expanded', 'false');
    menuOverlay.classList.remove('active');
    menuSheet.classList.remove('active');
    document.body.classList.remove('menu-open');

    setTimeout(() => {
      if (!burgerBtn.classList.contains('is-open')) {
        menuOverlay.hidden = true;
        menuSheet.hidden = true;
      }
    }, 300);
  };

  if (burgerBtn) {
    burgerBtn.addEventListener('click', () => {
      const isOpen = burgerBtn.classList.contains('is-open');
      if (isOpen) {
        closeMobileMenu();
      } else {
        openMobileMenu();
      }
    });
  }

  if (menuOverlay) {
    menuOverlay.addEventListener('click', closeMobileMenu);
  }

  document.querySelectorAll('.mobile-nav-link').forEach((link) => {
    link.addEventListener('click', () => {
      closeMobileMenu();
    });
  });

  window.addEventListener('resize', () => {
    if (window.innerWidth > 720 && burgerBtn && burgerBtn.classList.contains('is-open')) {
      closeMobileMenu();
    }
  });

  // ----------------------------------------------------
  // 4. AURORA SIGN UP MODAL CONTROLLER
  // ----------------------------------------------------
  const auroraModal = document.getElementById('auroraModal');
  const signInBtn = document.getElementById('signInBtn');
  const mobileSignInBtn = document.getElementById('mobileSignInBtn');
  const getStartedBtn = document.getElementById('getStartedBtn');
  const auroraCloseBtn = document.getElementById('auroraCloseBtn');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const passwordInput = document.getElementById('auroraPassword');
  const auroraForm = document.getElementById('auroraForm');
  const googleAuthBtn = document.getElementById('googleAuthBtn');
  const githubAuthBtn = document.getElementById('githubAuthBtn');

  const openAuroraModal = () => {
    if (!auroraModal) return;
    closeMobileMenu();
    auroraModal.hidden = false;
    void auroraModal.offsetWidth;
    auroraModal.classList.add('active');
    document.body.classList.add('modal-open');

    // Ensure hero video in modal plays
    const modalVideo = auroraModal.querySelector('.aurora-video');
    if (modalVideo) {
      modalVideo.play().catch(() => {});
    }
  };

  const closeAuroraModal = () => {
    if (!auroraModal) return;
    auroraModal.classList.remove('active');
    document.body.classList.remove('modal-open');
    setTimeout(() => {
      if (!auroraModal.classList.contains('active')) {
        auroraModal.hidden = true;
      }
    }, 300);
  };

  if (signInBtn) signInBtn.addEventListener('click', openAuroraModal);
  if (mobileSignInBtn) mobileSignInBtn.addEventListener('click', openAuroraModal);
  if (getStartedBtn) getStartedBtn.addEventListener('click', openAuroraModal);
  if (auroraCloseBtn) auroraCloseBtn.addEventListener('click', closeAuroraModal);

  // Close modal when clicking outside the dialog card
  if (auroraModal) {
    auroraModal.addEventListener('click', (e) => {
      if (e.target === auroraModal) {
        closeAuroraModal();
      }
    });
  }

  // Close modal with Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && auroraModal && !auroraModal.hidden) {
      closeAuroraModal();
    }
  });

  // Toggle Password Visibility
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', () => {
      const isPassword = passwordInput.getAttribute('type') === 'password';
      passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
      togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      
      // Update eye icon SVG
      if (isPassword) {
        togglePasswordBtn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
            <line x1="1" y1="1" x2="23" y2="23"></line>
          </svg>
        `;
      } else {
        togglePasswordBtn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
        `;
      }
    });
  }

  // Handle Form Submit
  if (auroraForm) {
    auroraForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = auroraForm.querySelector('button[type="submit"]');
      const originalText = submitBtn ? submitBtn.textContent : 'Create Account';
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Activating Identity...';
      }

      try {
        // Authenticate analyst session
        const res = await fetch('/api/auth/demo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: (document.getElementById('auroraFirstName')?.value || 'Lead') + ' ' + (document.getElementById('auroraLastName')?.value || 'Analyst'),
            email: document.getElementById('auroraEmail')?.value || 'analyst@phishchips.internal'
          })
        });
        
        if (submitBtn) submitBtn.textContent = 'Access Granted ✓';
        setTimeout(() => {
          window.location.href = '/console';
        }, 500);
      } catch (err) {
        console.error('Auth error:', err);
        window.location.href = '/console';
      }
    });
  }

  // Handle Google / GitHub Auth
  if (googleAuthBtn) {
    googleAuthBtn.addEventListener('click', async () => {
      googleAuthBtn.disabled = true;
      googleAuthBtn.style.opacity = '0.7';
      try {
        await fetch('/api/auth/demo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Google SecOps Lead',
            email: 'google-analyst@phishchips.internal'
          })
        });
        window.location.href = '/console';
      } catch (e) {
        window.location.href = '/console';
      }
    });
  }

  if (githubAuthBtn) {
    githubAuthBtn.addEventListener('click', async () => {
      githubAuthBtn.disabled = true;
      githubAuthBtn.style.opacity = '0.7';
      try {
        await fetch('/api/auth/demo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'GitHub Threat Researcher',
            email: 'gh-analyst@phishchips.internal'
          })
        });
        window.location.href = '/console';
      } catch (e) {
        window.location.href = '/console';
      }
    });
  }
});

