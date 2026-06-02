/* ═══════════════════════════════════════════════════════════════
   REDSTRYKE — PREMIUM JS ENGINE v2
   India's Most Advanced AI Red Team
   ═══════════════════════════════════════════════════════════════ */

// ── Config ──
const SUPABASE_URL = window.SUPABASE_URL || '';
const SUPABASE_ANON_KEY = window.SUPABASE_ANON_KEY || '';
const RAZORPAY_LINKS = {
  recon: 'https://rzp.io/l/redstryke-recon',
  assault: 'https://rzp.io/l/redstryke-assault',
  siege_monthly: 'https://rzp.io/l/redstryke-siege-monthly',
  siege_annual: 'https://rzp.io/l/redstryke-siege-annual',
};

let supabase = null;
let currentUser = null;
let siegeBilling = 'monthly';

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  console.log('REDSTRYKE Premium Interface loaded');
  initSupabase();
  checkAuth();
  initSmoothScroll();
  initScrollAnimations();
  initNavScroll();
  initMobileDrawer();
  initGlossaryTooltips();
  initStaggerAnimations();
  initParticleCanvas();
  initTrustCarousel();
  initLiveCounter();
  initRippleEffect();
  initMagneticButtons();
  initParallax();
  PageTransition.init();
});

// ── Supabase ──
async function initSupabase() {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) { console.warn('Supabase not configured'); return; }
  try {
    const { createClient } = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm');
    supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  } catch (e) { console.warn('Supabase SDK failed:', e); }
}

async function checkAuth() {
  if (!supabase) return;
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (user) { currentUser = user; updateNavForAuth(user); }
  } catch (e) { console.warn('Auth check failed:', e); }
}

function updateNavForAuth(user) {
  const navRight = document.querySelector('.nav-right');
  if (!navRight) return;
  const initials = (user.email || 'OP').substring(0, 2).toUpperCase();
  navRight.innerHTML = `
    <a href="/dashboard" class="btn btn-ghost">[ DASHBOARD ]</a>
    <div class="nav-user" style="position:relative;">
      <div class="nav-avatar" onclick="toggleUserMenu()">${initials}</div>
      <div class="nav-user-dropdown" id="userMenu">
        <a href="/dashboard">My Profile</a>
        <a href="/dashboard">My Engagements</a>
        <a href="/dashboard">Settings</a>
        <button onclick="signOut()">[ SIGN OUT ]</button>
      </div>
    </div>`;
}

function toggleUserMenu() { document.getElementById('userMenu')?.classList.toggle('show'); }
async function signOut() {
  if (!supabase) return;
  await supabase.auth.signOut(); currentUser = null; window.location.href = '/';
}
document.addEventListener('click', (e) => {
  if (!e.target.closest('.nav-user')) document.getElementById('userMenu')?.classList.remove('show');
});

// ── Smooth Scroll ──
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      const target = document.querySelector(anchor.getAttribute('href'));
      if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    });
  });
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 1: NAV SCROLL (transparent → glass blur)
// ═══════════════════════════════════════════════════════════════
function initNavScroll() {
  const nav = document.getElementById('mainNav');
  if (!nav) return;
  const observer = new IntersectionObserver(
    ([entry]) => { nav.classList.toggle('nav-scrolled', !entry.isIntersecting); },
    { rootMargin: '-64px 0px 0px 0px' }
  );
  const hero = document.getElementById('hero');
  if (hero) observer.observe(hero);
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 2: MOBILE DRAWER (slide-out)
// ═══════════════════════════════════════════════════════════════
function initMobileDrawer() {
  const btn = document.querySelector('.mobile-menu-btn');
  if (!btn) return;
  btn.addEventListener('click', () => { toggleMobileDrawer(); });
}

function toggleMobileDrawer() {
  let drawer = document.querySelector('.mobile-drawer');
  if (!drawer) { createMobileDrawer(); drawer = document.querySelector('.mobile-drawer'); }
  drawer.classList.toggle('open');
  document.querySelector('.mobile-drawer-overlay')?.classList.toggle('open');
  document.body.classList.toggle('no-scroll');
}

function createMobileDrawer() {
  const links = [
    { href: '#why-exist', label: 'The India Problem' },
    { href: '#how-it-works', label: 'How It Works' },
    { href: '#pricing', label: 'Pricing' },
    { href: '#why-india', label: 'Why India' },
  ];
  const overlay = document.createElement('div');
  overlay.className = 'mobile-drawer-overlay';
  overlay.onclick = toggleMobileDrawer;
  document.body.appendChild(overlay);

  const drawer = document.createElement('div');
  drawer.className = 'mobile-drawer';
  drawer.innerHTML = `
    <div class="mobile-drawer-header">
      <span class="mobile-drawer-logo">⧩ REDSTRYKE</span>
      <button class="mobile-drawer-close" onclick="toggleMobileDrawer()">&times;</button>
    </div>
    <div class="mobile-drawer-body">
      ${links.map(l => `<a href="${l.href}" onclick="toggleMobileDrawer()">${l.label}</a>`).join('')}
      <hr>
      <a href="/login" class="mobile-drawer-btn">LOGIN</a>
      <a href="/signup" class="mobile-drawer-btn mobile-drawer-btn-primary">REQUEST BRIEFING</a>
    </div>`;
  document.body.appendChild(drawer);
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 3: SCROLL ANIMATIONS (IntersectionObserver)
// ═══════════════════════════════════════════════════════════════
function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

  document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-scale, .stats-grid-5 > .stat-item, .why-card, .pricing-card, .addon-card, .capability-block, .agent-card').forEach(el => {
    observer.observe(el);
  });

  // Count-up animation
  const countObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.dataset.count);
        if (!target) return;
        animateCountUp(el, target);
        countObserver.unobserve(el);
      }
    });
  }, { threshold: 0.5 });

  document.querySelectorAll('[data-count]').forEach(el => countObserver.observe(el));
}

function animateCountUp(el, target) {
  const duration = 2000;
  const steps = 60;
  const increment = target / steps;
  let current = 0;
  let step = 0;
  const timer = setInterval(() => {
    step++;
    current = Math.min(Math.round(increment * step), target);
    el.textContent = current.toLocaleString('en-IN');
    if (step >= steps) { clearInterval(timer); el.textContent = target.toLocaleString('en-IN'); }
  }, duration / steps);
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 4: PARALLAX
// ═══════════════════════════════════════════════════════════════
function initParallax() {
  window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    document.querySelectorAll('.parallax-bg').forEach(el => {
      const speed = parseFloat(el.dataset.speed || '0.3');
      el.style.transform = `translateY(${scrolled * speed}px)`;
    });
  }, { passive: true });
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 5: PARTICLE CANVAS (hero background)
// ═══════════════════════════════════════════════════════════════
function initParticleCanvas() {
  const canvas = document.getElementById('particleCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let particles = [];
  let mouse = { x: -1000, y: -1000 };
  let animId;

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
  }

  function createParticles() {
    particles = [];
    const count = Math.min(Math.floor(canvas.width * 0.04), 70);
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * canvas.width, y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
        r: Math.random() * 1.5 + 0.5, alpha: Math.random() * 0.4 + 0.1,
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach((p, i) => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = canvas.width; if (p.x > canvas.width) p.x = 0;
      if (p.y < 0) p.y = canvas.height; if (p.y > canvas.height) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(239, 68, 68, ${p.alpha})`;
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[j].x - p.x, dy = particles[j].y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 150) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(239, 68, 68, ${0.08 * (1 - dist / 150)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    });
    animId = requestAnimationFrame(draw);
  }

  resize();
  createParticles();
  draw();

  canvas.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX - canvas.getBoundingClientRect().left;
    mouse.y = e.clientY - canvas.getBoundingClientRect().top;
    particles.forEach(p => {
      const dx = mouse.x - p.x, dy = mouse.y - p.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 100) { p.vx += dx * 0.0002; p.vy += dy * 0.0002; }
    });
  });

  window.addEventListener('resize', () => { resize(); createParticles(); });
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 6: TRUST CAROUSEL (testimonials)
// ═══════════════════════════════════════════════════════════════
function initTrustCarousel() {
  const track = document.querySelector('.testimonial-track');
  const dots = document.querySelectorAll('.carousel-dot');
  const prev = document.querySelector('.carousel-arrow-prev');
  const next = document.querySelector('.carousel-arrow-next');
  if (!track || !dots.length) return;

  let current = 0; const total = dots.length;

  function goTo(index) {
    current = ((index % total) + total) % total;
    track.style.transform = `translateX(-${current * 100}%)`;
    dots.forEach((d, i) => d.classList.toggle('active', i === current));
  }

  dots.forEach(d => d.addEventListener('click', () => goTo(parseInt(d.dataset.index))));
  if (prev) prev.addEventListener('click', () => goTo(current - 1));
  if (next) next.addEventListener('click', () => goTo(current + 1));

  let autoTimer = setInterval(() => goTo(current + 1), 6000);
  document.querySelector('.testimonials-section')?.addEventListener('mouseenter', () => clearInterval(autoTimer));
  document.querySelector('.testimonials-section')?.addEventListener('mouseleave', () => {
    autoTimer = setInterval(() => goTo(current + 1), 6000);
  });
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 7: LIVE COUNTER
// ═══════════════════════════════════════════════════════════════
function initLiveCounter() {
  const el = document.getElementById('liveCounter');
  if (!el) return;
  let count = 2847;
  setInterval(() => {
    count += Math.floor(Math.random() * 3) + 1;
    el.textContent = count.toLocaleString('en-IN');
  }, 3000);
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 8: RIPPLE EFFECT ON BUTTONS
// ═══════════════════════════════════════════════════════════════
function initRippleEffect() {
  document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', function (e) {
      const rect = this.getBoundingClientRect();
      const ripple = document.createElement('span');
      ripple.className = 'ripple';
      const size = Math.max(rect.width, rect.height);
      ripple.style.width = ripple.style.height = size + 'px';
      ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
      ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
      this.appendChild(ripple);
      setTimeout(() => ripple.remove(), 600);
    });
  });
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 9: MAGNETIC BUTTONS
// ═══════════════════════════════════════════════════════════════
function initMagneticButtons() {
  document.querySelectorAll('.btn-large, .btn-block').forEach(btn => {
    btn.addEventListener('mousemove', (e) => {
      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      btn.style.transform = `translate(${x * 0.1}px, ${y * 0.1}px)`;
    });
    btn.addEventListener('mouseleave', () => { btn.style.transform = ''; });
  });
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 10: GLOSSARY TOOLTIPS
// ═══════════════════════════════════════════════════════════════
const GLOSSARY = {
  certin: { term: 'CERT-In', def: 'Indian Computer Emergency Response Team — India\'s national nodal agency for cybersecurity incident reporting and response. Mandates breach reporting within 6 hours.' },
  dpdpa: { term: 'DPDPA', def: 'Digital Personal Data Protection Act 2023 — India\'s comprehensive data protection law. Penalties up to ₹250 crore per violation. Full enforcement by May 2027.' },
  rbi: { term: 'RBI IT Framework', def: 'Reserve Bank of India\'s IT governance and cybersecurity framework for regulated financial entities in India.' },
  sebi: { term: 'SEBI CSCRF', def: 'Securities and Exchange Board of India\'s Cyber Security and Cyber Resilience Framework for market infrastructure institutions.' },
};

function initGlossaryTooltips() {
  const tooltip = document.getElementById('glossaryTooltip');
  if (!tooltip) return;

  document.querySelectorAll('.glossary-trigger').forEach(el => {
    el.addEventListener('mouseenter', (e) => {
      const term = el.dataset.term;
      const data = GLOSSARY[term];
      if (!data) return;
      tooltip.innerHTML = `<div class="gloss-term">${data.term}</div><div class="gloss-def">${data.def}</div>`;
      tooltip.classList.add('show');
      positionTooltip(el, tooltip);
    });
    el.addEventListener('mousemove', () => { positionTooltip(el, tooltip); });
    el.addEventListener('mouseleave', () => { tooltip.classList.remove('show'); });
  });
}

function positionTooltip(trigger, tooltip) {
  const tr = trigger.getBoundingClientRect();
  const tt = tooltip.getBoundingClientRect();
  let left = tr.left + tr.width / 2 - tt.width / 2;
  let top = tr.top - tt.height - 10;
  if (left < 10) left = 10;
  if (left + tt.width > window.innerWidth - 10) left = window.innerWidth - tt.width - 10;
  if (top < 10) top = tr.bottom + 10;
  tooltip.style.left = left + 'px';
  tooltip.style.top = top + 'px';
}

// ═══════════════════════════════════════════════════════════════
//  PREMIUM FEATURE 11: STAGGER ANIMATIONS (data-delay)
// ═══════════════════════════════════════════════════════════════
function initStaggerAnimations() {
  document.querySelectorAll('[data-delay]').forEach(el => {
    const delay = parseInt(el.dataset.delay) || 0;
    el.style.animationDelay = delay + 'ms';
  });

  // Sector bar fill animation on scroll
  const barObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.transition = 'width 1s ease-out';
        entry.target.style.width = entry.target.dataset.width || entry.target.style.width;
        barObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });
  document.querySelectorAll('.sector-fill').forEach(el => {
    el.dataset.width = el.style.width;
    el.style.width = '0%';
    barObserver.observe(el);
  });
}

// ═══════════════════════════════════════════════════════════════
//  PAGE TRANSITION
// ═══════════════════════════════════════════════════════════════
const PageTransition = {
  init() {
    const overlay = document.createElement('div');
    overlay.className = 'page-transition';
    overlay.id = 'pageTransition';
    document.body.appendChild(overlay);

    document.querySelectorAll('a:not([href^="#"]):not([href^="javascript"]):not([href^="tel"]):not([href^="mailto"])').forEach(a => {
      if (a.hostname === window.location.hostname && !a.hasAttribute('target')) {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const href = a.href;
          this.play(() => { window.location.href = href; });
        });
      }
    });
  },
  play(callback) {
    const el = document.getElementById('pageTransition');
    if (el) {
      el.classList.add('active');
      setTimeout(() => { if (callback) callback(); }, 400);
    } else if (callback) callback();
  }
};

// ═══════════════════════════════════════════════════════════════
//  TAB FUNCTIONS
// ═══════════════════════════════════════════════════════════════
function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(tabId)?.classList.add('active');
}

function switchDocTab(tabId, btn) {
  document.querySelectorAll('.doc-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.doc-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(tabId)?.classList.add('active');
}

// ── Pricing ──
function toggleBilling(period, btn) {
  siegeBilling = period;
  document.querySelectorAll('.billing-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const priceEl = document.getElementById('siege-price');
  const periodEl = document.getElementById('siege-period');
  const savingsEl = document.getElementById('siege-savings');
  const ctaBtn = document.querySelector('.card-siege .btn-block');

  if (period === 'annual') {
    priceEl.textContent = '₹4,99,999';
    periodEl.textContent = '/ YEAR';
    if (savingsEl) { savingsEl.style.display = 'inline-block'; savingsEl.textContent = 'SAVE ₹1,00,000 — 2 MONTHS FREE'; }
    if (ctaBtn) ctaBtn.textContent = '[ BEGIN SIEGE — ₹4,99,999/YR ]';
  } else {
    priceEl.textContent = '₹49,999';
    periodEl.textContent = '/ MONTH';
    if (savingsEl) { savingsEl.style.display = 'none'; }
    if (ctaBtn) ctaBtn.textContent = '[ BEGIN SIEGE — ₹49,999/MO ]';
  }

  // Animate price change
  if (priceEl) {
    priceEl.style.transition = 'transform 0.3s ease, opacity 0.3s ease';
    priceEl.style.transform = 'scale(1.1)';
    priceEl.style.opacity = '0.7';
    setTimeout(() => {
      priceEl.style.transform = 'scale(1)';
      priceEl.style.opacity = '1';
    }, 150);
  }
}

function openRazorpay(tier) {
  let link;
  switch (tier) {
    case 'recon': link = RAZORPAY_LINKS.recon; break;
    case 'assault': link = RAZORPAY_LINKS.assault; break;
    case 'siege': link = siegeBilling === 'annual' ? RAZORPAY_LINKS.siege_annual : RAZORPAY_LINKS.siege_monthly; break;
    default: return;
  }
  if (link) { window.open(link, '_blank'); }
  else { alert('Payment link coming soon. Contact us on WhatsApp for early access.'); }
}

// ── Modals ──
function openClassifiedForm() { document.getElementById('classifiedModal').classList.add('active'); }
function submitClassified(e) { e.preventDefault(); alert('Your briefing request has been submitted. Our team will contact you within 24 hours.'); closeModal('classifiedModal'); }
function openAddonForm(name) { document.getElementById('addonNameDisplay').textContent = name; document.getElementById('addonModal').classList.add('active'); }
function submitAddon(e) { e.preventDefault(); alert(`Your request for "${document.getElementById('addonNameDisplay').textContent}" has been submitted. We'll reach out shortly.`); closeModal('addonModal'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

// ── Auth ──
async function authenticate() {
  const email = document.getElementById('auth-email')?.value;
  const password = document.getElementById('auth-password')?.value;
  const errorEl = document.getElementById('auth-error');
  const btn = document.querySelector('.auth-btn-primary');
  if (!supabase) {
    if (errorEl) { errorEl.textContent = 'AUTH SYSTEM OFFLINE — Contact ops@redstryke.in'; errorEl.classList.add('show'); }
    return;
  }
  if (!email || !password) {
    if (errorEl) { errorEl.textContent = 'ACCESS DENIED — All fields required'; errorEl.classList.add('show'); }
    return;
  }
  btn?.classList.add('loading');
  errorEl?.classList.remove('show');
  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    window.location.href = '/dashboard';
  } catch (e) {
    btn?.classList.remove('loading');
    if (errorEl) { errorEl.textContent = 'ACCESS DENIED — Invalid credentials'; errorEl.classList.add('show'); }
    const card = document.querySelector('.auth-card');
    if (card) { card.classList.add('shake'); setTimeout(() => card.classList.remove('shake'), 500); }
  }
}

async function continueWith(provider) {
  if (!supabase) { alert('Auth system offline.'); return; }
  try { await supabase.auth.signInWithOAuth({ provider }); }
  catch (e) { alert('OAuth failed: ' + e.message); }
}

async function forgotCipherKey() {
  if (!supabase) { alert('Auth system offline. Contact ops@redstryke.in'); return; }
  const email = prompt('Enter your OPERATOR ID (email):');
  if (!email) return;
  try {
    await supabase.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin + '/login' });
    alert('Password reset link sent to your email.');
  } catch (e) { alert('Failed: ' + e.message); }
}

// ── Signup ──
let signupStep = 1;
let signupData = {};

function nextSignupStep() {
  const currentEl = document.getElementById(`signup-step-${signupStep}`);
  const stepDots = document.querySelectorAll('.auth-step');

  if (signupStep === 1) {
    const name = document.getElementById('signup-name')?.value;
    const org = document.getElementById('signup-org')?.value;
    if (!name || !org) { alert('All fields required'); return; }
    signupData.full_name = name; signupData.organization = org; signupData.role = document.getElementById('signup-role')?.value || 'Other';
    signupData.phone = document.getElementById('signup-phone')?.value || ''; signupData.whatsapp_opted_in = document.getElementById('signup-whatsapp')?.checked || false;
  }
  if (signupStep === 2) {
    const email = document.getElementById('signup-email')?.value;
    const password = document.getElementById('signup-password')?.value;
    const confirm = document.getElementById('signup-confirm')?.value;
    if (!email || !password) { alert('All fields required'); return; }
    if (password.length < 10) { alert('CIPHER KEY must be at least 10 characters'); return; }
    if (password !== confirm) { alert('CIPHER KEYs do not match'); return; }
    signupData.email = email; signupData.password = password;
  }
  if (signupStep === 3) {
    signupData.company_size = document.querySelector('.radio-card.selected')?.textContent || '';
    signupData.primary_concerns = Array.from(document.querySelectorAll('.checkbox-item input:checked')).map(cb => cb.value);
    signupData.compliance = document.querySelector('input[name="compliance"]:checked')?.value || '';
    signupData.referral_source = document.getElementById('signup-referral')?.value || '';
  }

  if (currentEl) currentEl.classList.remove('active');
  if (signupStep < 4) {
    signupStep++;
    stepDots[signupStep - 1]?.classList.add('active');
    stepDots[signupStep - 2]?.classList.add('completed');
    const nextEl = document.getElementById(`signup-step-${signupStep}`);
    if (nextEl) nextEl.classList.add('active');
    if (signupStep === 4) finishSignup();
  }
}

function selectRadio(el) {
  el.closest('.radio-card-group')?.querySelectorAll('.radio-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
}
function toggleCheckboxItem(el) { el.classList.toggle('selected'); const cb = el.querySelector('input'); if (cb) cb.checked = !cb.checked; }

async function finishSignup() {
  const operatorName = document.getElementById('signup-name')?.value || 'OPERATOR';
  document.querySelector('.operator-badge .callsign') && (document.querySelector('.operator-badge .callsign').textContent = operatorName.toUpperCase());
  document.getElementById('signup-display-name') && (document.getElementById('signup-display-name').textContent = operatorName);
  if (!supabase) { console.warn('Supabase not configured — signup simulated'); return; }
  try {
    const { data, error } = await supabase.auth.signUp({ email: signupData.email, password: signupData.password, options: { data: { full_name: signupData.full_name, organization: signupData.organization, role: signupData.role } } });
    if (error) throw error;
    if (data.user) {
      await supabase.from('operator_profiles').insert([{ id: data.user.id, full_name: signupData.full_name, organization: signupData.organization, role: signupData.role, company_size: signupData.company_size, primary_concerns: signupData.primary_concerns, phone: signupData.phone, whatsapp_opted_in: signupData.whatsapp_opted_in, tier_interest: '', country: 'India' }]);
    }
  } catch (e) { console.error('Signup failed:', e); }
}

function checkPasswordStrength(pw) {
  const bars = document.querySelectorAll('.strength-bar');
  const label = document.querySelector('.strength-label');
  let strength = 0;
  if (pw.length >= 10) strength++; if (pw.length >= 14) strength++;
  if (/[A-Z]/.test(pw)) strength++; if (/[0-9]/.test(pw)) strength++;
  if (/[^A-Za-z0-9]/.test(pw)) strength++;
  const levels = ['', 'weak', 'moderate', 'strong', 'fortress'];
  const names = ['', 'Weak', 'Moderate', 'Strong', 'Fortress'];
  bars.forEach((bar, i) => { bar.className = 'strength-bar'; if (i < strength) bar.classList.add(levels[strength] || 'weak'); });
  if (label) label.textContent = names[strength] || '';
}

// ── ROI Calculator ──
function updateROI() {
  const slider = document.getElementById('roiSlider');
  const industry = document.getElementById('roiIndustry');
  const sizeDisplay = document.getElementById('roiSize');
  const amountDisplay = document.getElementById('roiAmount');
  if (!slider || !industry || !sizeDisplay || !amountDisplay) return;

  const size = parseInt(slider.value);
  sizeDisplay.textContent = size + ' GB';

  const multipliers = { fintech: 22000000, healthcare: 18000000, ecommerce: 12000000, saas: 15000000, govt: 25000000 };
  const mult = multipliers[industry.value] || 15000000;
  const estimated = Math.round((size / 100) * mult);
  const formatted = '₹' + (estimated / 100000).toFixed(1) + ',' + (estimated % 100000).toLocaleString('en-IN').padStart(5, '0');

  amountDisplay.textContent = '₹' + estimated.toLocaleString('en-IN');
}

// ── Urgency bar ──
(function initUrgencyBar() {
  const track = document.querySelector('.urgency-track');
  if (track) { track.innerHTML += track.innerHTML; }
})();

// ── Expose to window ──
window.toggleMobileMenu = toggleMobileDrawer;
window.toggleBilling = toggleBilling;
window.openRazorpay = openRazorpay;
window.openClassifiedForm = openClassifiedForm;
window.submitClassified = submitClassified;
window.openAddonForm = openAddonForm;
window.submitAddon = submitAddon;
window.closeModal = closeModal;
window.authenticate = authenticate;
window.continueWith = continueWith;
window.forgotCipherKey = forgotCipherKey;
window.nextSignupStep = nextSignupStep;
window.selectRadio = selectRadio;
window.toggleCheckboxItem = toggleCheckboxItem;
window.checkPasswordStrength = checkPasswordStrength;
window.toggleUserMenu = toggleUserMenu;
window.signOut = signOut;
window.switchTab = switchTab;
window.switchDocTab = switchDocTab;
window.updateROI = updateROI;
