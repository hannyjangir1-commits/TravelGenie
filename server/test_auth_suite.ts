import express from 'express';
import cookieParser from 'cookie-parser';
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
import type { GeneratePlanRequest, TravelPlan } from './src/types.js';

async function runTestSuite() {
  console.log('=====================================================');
  console.log('STARTING TRAVELGENIE AUTHENTICATION VERIFICATION SUITE');
  console.log('=====================================================\n');

  let passedTests = 0;
  let totalTests = 0;

  function assert(condition: boolean, testName: string, details?: string) {
    totalTests++;
    if (condition) {
      console.log(`✓ [PASS] ${testName}`);
      passedTests++;
    } else {
      console.error(`✗ [FAIL] ${testName}${details ? ` - Details: ${details}` : ''}`);
    }
  }

  // TEST 1: Password hashing and validation
  console.log('--- TEST GROUP 1: PASSWORD SECURITY & HASHING ---');
  const plainPass = 'SuperSecret123!';
  const hashed = await hashPassword(plainPass);
  assert(hashed !== plainPass, 'Password is never stored or hashed as plaintext');
  assert(hashed.startsWith('$2'), 'Password hashed with bcrypt algorithm ($2a/$2b)');
  assert(await comparePassword(plainPass, hashed), 'Correct password successfully matches hash');
  assert(!(await comparePassword('WrongPassword!', hashed)), 'Incorrect password fails hash comparison');

  const shortPassValidation = validateSignupInput({ name: 'John', email: 'john@test.com', password: '123' });
  assert(!shortPassValidation.isValid, 'Reject password shorter than 8 characters');

  const emptyPassValidation = validateSignupInput({ name: 'John', email: 'john@test.com', password: '   ' });
  assert(!emptyPassValidation.isValid, 'Reject empty/whitespace-only password');

  // TEST 2: Signup API behavior
  console.log('\n--- TEST GROUP 2: SIGNUP API ---');
  const testEmailA = `testuser_${Date.now()}@example.com`;
  const invalidEmailValidation = validateSignupInput({ name: 'Valid Name', email: 'invalid-email', password: 'ValidPassword123' });
  assert(!invalidEmailValidation.isValid, 'Reject invalid email format');

  const validSignupValidation = validateSignupInput({ name: 'Traveler One', email: testEmailA, password: 'StrongPassword123' });
  assert(validSignupValidation.isValid, 'Accept valid signup input payload');

  const createdUser = await createUser('Traveler One', testEmailA, await hashPassword('StrongPassword123'));
  assert(Boolean(createdUser.id), 'Create user produces unique user id');
  assert(createdUser.email === testEmailA.toLowerCase(), 'Email normalized to lowercase');
  assert(!('password_hash' in createdUser), 'Created user object NEVER exposes password_hash');

  const duplicateCheck = await findUserByEmail(testEmailA);
  assert(duplicateCheck !== null, 'Existing email correctly detected for 409 conflict handling');

  // TEST 3: Signin API behavior
  console.log('\n--- TEST GROUP 3: SIGNIN API ---');
  // A. Email does not exist
  const nonExistent = await findUserByEmail('doesnotexist_999@domain.com');
  assert(nonExistent === null, 'Non-existent email returns null for 404 / USER_NOT_FOUND redirection');

  // B. Email exists, wrong password
  const userA = await findUserByEmail(testEmailA);
  assert(userA !== null, 'Found user for signin');
  const isWrongMatch = await comparePassword('CompletelyWrongPass', userA!.password_hash!);
  assert(!isWrongMatch, 'Incorrect password rejected (returns 401 generic error, no redirect)');

  // C. Correct credentials
  const isCorrectMatch = await comparePassword('StrongPassword123', userA!.password_hash!);
  assert(isCorrectMatch, 'Correct credentials successfully validated');
  const safeUserA = toSafeUser(userA!);
  assert(!('password_hash' in safeUserA), 'toSafeUser NEVER contains password_hash');
  assert(safeUserA.email === testEmailA.toLowerCase(), 'Safe user preserves email');

  // TEST 4: JWT & Cookie security
  console.log('\n--- TEST GROUP 4: JWT & HTTP-ONLY COOKIE ---');
  const token = signAuthToken({ userId: safeUserA.id, email: safeUserA.email });
  assert(typeof token === 'string' && token.length > 20, 'JWT token signed successfully');

  const verified = verifyAuthToken(token);
  assert(verified !== null && verified.userId === safeUserA.id, 'JWT token decoded and verified successfully');

  const invalidToken = verifyAuthToken('tampered.invalid.token');
  assert(invalidToken === null, 'Invalid/tampered JWT safely rejected');

  const cookieOpts = getAuthCookieOptions();
  assert(cookieOpts.httpOnly === true, 'Cookie has httpOnly: true (prevents XSS theft)');
  assert(cookieOpts.sameSite === 'lax', 'Cookie has sameSite: lax');

  // TEST 5: Travel Plan Ownership & Isolation (Requirement 8)
  console.log('\n--- TEST GROUP 5: TRAVEL PLAN OWNERSHIP & ISOLATION ---');
  const sampleRequest: GeneratePlanRequest = {
    destination: 'Goa',
    numberOfDays: 3,
    budgetInr: 25000,
    numberOfTravellers: 2,
    interests: ['Beach', 'Food'],
    accommodationPreference: 'Moderate',
    activityLevel: 'Relaxed'
  };

  const samplePlan: TravelPlan = {
    accommodationGuidance: 'Stay near North Goa beaches',
    placesToVisit: [{ name: 'Anjuna Beach', reason: 'Sunset views', bestTime: 'Late afternoon' }],
    foodAndLocalExperiences: [{ name: 'Goan Fish Curry', reason: 'Local delicacy' }],
    activities: [{ name: 'Water sports', reason: 'Exciting coastal sports' }],
    weatherAdvice: 'Warm and breezy',
    budgetTips: ['Rent a scooter to save transport costs'],
    itinerary: [{
      day: 1,
      morning: 'Arrive and check in',
      afternoon: 'Relax at beach',
      evening: 'Sunset dinner',
      notes: 'Take coastal taxi',
      alternative: 'Indoor cafe if raining'
    }]
  };

  // User A saves travel plan
  const savedPlanA = await saveUserTravelPlan(safeUserA.id, sampleRequest, samplePlan);
  assert(Boolean(savedPlanA.id), 'Travel plan saved with user ownership');
  assert(savedPlanA.user_id === safeUserA.id, 'Travel plan correctly associated with User A user_id');

  // User A can access User A's plans
  const userAPlans = await getUserTravelPlans(safeUserA.id);
  assert(userAPlans.some(p => p.id === savedPlanA.id), 'User A can view their own travel plans in history');

  const fetchedPlanByIdA = await getUserTravelPlanById(savedPlanA.id, safeUserA.id);
  assert(fetchedPlanByIdA !== null && fetchedPlanByIdA.id === savedPlanA.id, 'User A can access specific plan by ID');

  // Create User B
  const testEmailB = `user_b_${Date.now()}@example.com`;
  const userB = await createUser('Traveler Two', testEmailB, await hashPassword('StrongPassword456!'));

  // User B history check - must NOT contain User A's plan
  const userBPlans = await getUserTravelPlans(userB.id);
  assert(!userBPlans.some(p => p.id === savedPlanA.id), 'User B history does NOT contain User A plans (Strict Isolation)');

  // User B attempts to access User A's specific plan by ID
  const crossUserAccess = await getUserTravelPlanById(savedPlanA.id, userB.id);
  assert(crossUserAccess === null, 'Cross-user plan access strictly blocked (returns null -> 404)');

  console.log('\n=====================================================');
  console.log(`TEST SUITE FINISHED: ${passedTests}/${totalTests} TESTS PASSED`);
  console.log('=====================================================');

  if (passedTests === totalTests) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal error in test suite:', err);
  process.exit(1);
});
