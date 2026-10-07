import http from 'http';
import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import {
  AUTH_COOKIE_NAME,
  getAuthCookieOptions,
  validateSignupInput,
  validateSigninInput,
  findUserByEmail,
  findUserById,
  createUser,
  hashPassword,
  comparePassword,
  signAuthToken,
  verifyAuthToken,
  requireAuth,
  optionalAuth,
  toSafeUser,
  type AuthenticatedRequest
} from './src/auth.js';
import {
  saveUserTravelPlan,
  getUserTravelPlans,
  getUserTravelPlanById
} from './src/travelPlanService.js';

const app = express();
app.use(express.json());
app.use(cookieParser());

// Replicate routes from index.ts
app.post('/api/auth/signup', async (req: Request, res: Response) => {
  const validation = validateSignupInput(req.body);
  if (!validation.isValid || !validation.data) {
    res.status(400).json({ success: false, error: validation.error });
    return;
  }
  const { name, email, password } = validation.data;
  const existing = await findUserByEmail(email);
  if (existing) {
    res.status(409).json({ success: false, error: 'An account with this email already exists.' });
    return;
  }
  const hashedPassword = await hashPassword(password);
  const newUser = await createUser(name, email, hashedPassword);
  const token = signAuthToken({ userId: newUser.id, email: newUser.email });
  res.cookie(AUTH_COOKIE_NAME, token, getAuthCookieOptions());
  res.status(201).json({ success: true, authenticated: true, user: newUser });
});

app.post('/api/auth/signin', async (req: Request, res: Response) => {
  const validation = validateSigninInput(req.body);
  if (!validation.isValid || !validation.data) {
    res.status(400).json({ success: false, error: validation.error });
    return;
  }
  const { email, password } = validation.data;
  const user = await findUserByEmail(email);
  if (!user) {
    res.status(404).json({ success: false, code: 'USER_NOT_FOUND', notFound: true, error: 'No account found.' });
    return;
  }
  if (!user.password_hash || !(await comparePassword(password, user.password_hash))) {
    res.status(401).json({ success: false, code: 'INVALID_CREDENTIALS', error: 'Invalid email or password.' });
    return;
  }
  const token = signAuthToken({ userId: user.id, email: user.email });
  res.cookie(AUTH_COOKIE_NAME, token, getAuthCookieOptions());
  res.json({ success: true, authenticated: true, user: toSafeUser(user) });
});

app.get('/api/auth/me', async (req: AuthenticatedRequest, res: Response) => {
  const token = req.cookies?.[AUTH_COOKIE_NAME];
  if (!token) {
    res.json({ authenticated: false, user: null });
    return;
  }
  const payload = verifyAuthToken(token);
  if (!payload) {
    res.json({ authenticated: false, user: null });
    return;
  }
  const user = await findUserById(payload.userId);
  if (!user) {
    res.json({ authenticated: false, user: null });
    return;
  }
  res.json({ authenticated: true, user: toSafeUser(user) });
});

app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie(AUTH_COOKIE_NAME, getAuthCookieOptions());
  res.json({ success: true, authenticated: false, message: 'Logged out successfully.' });
});

app.get('/api/travel-plans', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const plans = await getUserTravelPlans(req.user!.userId);
  res.json({ success: true, data: plans });
});

app.get('/api/travel-plans/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const plan = await getUserTravelPlanById(req.params.id, req.user!.userId);
  if (!plan) {
    res.status(404).json({ success: false, error: 'Plan not found.' });
    return;
  }
  res.json({ success: true, data: plan });
});

async function runHttpTests() {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(5099, resolve));
  console.log('HTTP Test Server running on port 5099\n');

  let passed = 0;
  let total = 0;
  function testAssert(cond: boolean, name: string) {
    total++;
    if (cond) {
      console.log(`✓ [PASS] ${name}`);
      passed++;
    } else {
      console.error(`✗ [FAIL] ${name}`);
    }
  }

  try {
    // 1. GET /api/auth/me without cookie
    const meRes1 = await fetch('http://localhost:5099/api/auth/me');
    const meData1 = await meRes1.json();
    testAssert(meData1.authenticated === false && meData1.user === null, 'GET /api/auth/me unauthenticated returns authenticated: false');

    // 2. POST /api/auth/signup short password
    const badPassRes = await fetch('http://localhost:5099/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Short', email: 'short@test.com', password: '123' })
    });
    testAssert(badPassRes.status === 400, 'POST /api/auth/signup with <8 char password returns 400 Bad Request');

    // 3. POST /api/auth/signup valid
    const userEmail = `http_test_${Date.now()}@test.com`;
    const signupRes = await fetch('http://localhost:5099/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alice Walker', email: userEmail, password: 'SecurePassword2026!' })
    });
    const signupCookie = signupRes.headers.get('set-cookie');
    const signupData = await signupRes.json();
    testAssert(signupRes.status === 201, 'POST /api/auth/signup returns 201 Created');
    testAssert(signupData.authenticated === true && signupData.user?.email === userEmail, 'POST /api/auth/signup returns authenticated user');
    testAssert(!('password_hash' in signupData.user), 'POST /api/auth/signup NEVER exposes password_hash');
    testAssert(signupCookie !== null && signupCookie.includes('travelgenie_auth') && signupCookie.includes('HttpOnly'), 'POST /api/auth/signup sets travelgenie_auth HTTP-only cookie');

    // Extract cookie value for subsequent requests
    const cookieHeader = signupCookie ? signupCookie.split(';')[0] : '';

    // 4. POST /api/auth/signup duplicate email
    const dupRes = await fetch('http://localhost:5099/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alice Duplicate', email: userEmail, password: 'AnotherPassword123!' })
    });
    testAssert(dupRes.status === 409, 'POST /api/auth/signup duplicate email returns 409 Conflict');

    // 5. GET /api/auth/me with cookie
    const meRes2 = await fetch('http://localhost:5099/api/auth/me', {
      headers: { Cookie: cookieHeader }
    });
    const meData2 = await meRes2.json();
    testAssert(meData2.authenticated === true && meData2.user?.name === 'Alice Walker', 'GET /api/auth/me with cookie returns authenticated profile');

    // 6. POST /api/auth/signin non-existent email
    const notFoundRes = await fetch('http://localhost:5099/api/auth/signin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ghost_account@test.com', password: 'SomePassword123!' })
    });
    const notFoundData = await notFoundRes.json();
    testAssert(notFoundRes.status === 404 && notFoundData.notFound === true, 'POST /api/auth/signin non-existent email returns 404 for signup redirection');

    // 7. POST /api/auth/signin incorrect password
    const wrongPassRes = await fetch('http://localhost:5099/api/auth/signin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userEmail, password: 'WrongPassword999!' })
    });
    const wrongPassData = await wrongPassRes.json();
    testAssert(wrongPassRes.status === 401 && wrongPassData.code === 'INVALID_CREDENTIALS', 'POST /api/auth/signin incorrect password returns 401 (no redirect)');

    // 8. POST /api/auth/signin correct password
    const signinRes = await fetch('http://localhost:5099/api/auth/signin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userEmail, password: 'SecurePassword2026!' })
    });
    const signinData = await signinRes.json();
    const signinCookie = signinRes.headers.get('set-cookie');
    testAssert(signinRes.status === 200 && signinData.authenticated === true, 'POST /api/auth/signin succeeds with status 200');
    testAssert(signinCookie !== null && signinCookie.includes('travelgenie_auth'), 'POST /api/auth/signin sets travelgenie_auth cookie');

    // 9. Protected travel plans without auth
    const plansUnauthRes = await fetch('http://localhost:5099/api/travel-plans');
    testAssert(plansUnauthRes.status === 401, 'GET /api/travel-plans without auth returns 401 Unauthorized');

    // 10. Protected travel plans with auth
    const plansAuthRes = await fetch('http://localhost:5099/api/travel-plans', {
      headers: { Cookie: cookieHeader }
    });
    const plansAuthData = await plansAuthRes.json();
    testAssert(plansAuthRes.status === 200 && Array.isArray(plansAuthData.data), 'GET /api/travel-plans with auth returns 200 and plans list');

    // 11. POST /api/auth/logout
    const logoutRes = await fetch('http://localhost:5099/api/auth/logout', {
      method: 'POST',
      headers: { Cookie: cookieHeader }
    });
    const logoutCookie = logoutRes.headers.get('set-cookie');
    const logoutData = await logoutRes.json();
    testAssert(logoutRes.status === 200 && logoutData.authenticated === false, 'POST /api/auth/logout returns 200 and authenticated: false');
    testAssert(logoutCookie !== null && (logoutCookie.includes('Max-Age=0') || logoutCookie.includes('travelgenie_auth=;')), 'POST /api/auth/logout clears travelgenie_auth cookie');

  } finally {
    server.close();
  }

  console.log(`\nHTTP TEST RESULT: ${passed}/${total} PASSED\n`);
  if (passed === total) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runHttpTests().catch((e) => {
  console.error('HTTP test error:', e);
  process.exit(1);
});
