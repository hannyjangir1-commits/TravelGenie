import { pool } from './db.js';
import type { GeneratePlanRequest, TravelPlan, TravelPlanRecord } from './types.js';

// In-memory fallback for development without live PostgreSQL
const inMemoryPlans: Map<string, TravelPlanRecord> = new Map();

/**
 * Saves a generated travel plan associated with the authenticated user's ID.
 */
export async function saveUserTravelPlan(
  userId: string,
  details: GeneratePlanRequest,
  plan: TravelPlan
): Promise<TravelPlanRecord> {
  if (process.env.DATABASE_URL) {
    try {
      const query = `
        INSERT INTO travel_plans (
          user_id,
          destination,
          number_of_days,
          budget_inr,
          number_of_travellers,
          interests,
          accommodation_preference,
          activity_level,
          additional_notes,
          plan_data
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, user_id, destination, number_of_days, budget_inr, number_of_travellers, interests, accommodation_preference, activity_level, additional_notes, plan_data, created_at, updated_at;
      `;
      const values = [
        userId,
        details.destination,
        details.numberOfDays,
        details.budgetInr,
        details.numberOfTravellers,
        JSON.stringify(details.interests),
        details.accommodationPreference,
        details.activityLevel,
        details.additionalNotes || null,
        JSON.stringify(plan)
      ];

      const result = await pool.query(query, values);
      return result.rows[0];
    } catch (err) {
      console.error('[DB] Error saving travel plan to PostgreSQL:', err instanceof Error ? err.message : err);
    }
  }

  // Fallback in-memory storage
  const id = `plan-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  const record: TravelPlanRecord = {
    id,
    user_id: userId,
    destination: details.destination,
    number_of_days: details.numberOfDays,
    budget_inr: details.budgetInr,
    number_of_travellers: details.numberOfTravellers,
    interests: details.interests,
    accommodation_preference: details.accommodationPreference,
    activity_level: details.activityLevel,
    additional_notes: details.additionalNotes || null,
    plan_data: plan,
    created_at: new Date(),
    updated_at: new Date()
  };
  inMemoryPlans.set(id, record);
  return record;
}

/**
 * Retrieves all travel plans owned by the authenticated user.
 */
export async function getUserTravelPlans(userId: string): Promise<TravelPlanRecord[]> {
  if (process.env.DATABASE_URL) {
    try {
      const query = `
        SELECT id, user_id, destination, number_of_days, budget_inr, number_of_travellers, interests, accommodation_preference, activity_level, additional_notes, plan_data, created_at, updated_at
        FROM travel_plans
        WHERE user_id = $1
        ORDER BY created_at DESC;
      `;
      const result = await pool.query(query, [userId]);
      return result.rows;
    } catch (err) {
      console.error('[DB] Error retrieving user travel plans from PostgreSQL:', err instanceof Error ? err.message : err);
    }
  }

  // Fallback in-memory retrieval
  const userPlans: TravelPlanRecord[] = [];
  for (const p of inMemoryPlans.values()) {
    if (p.user_id === userId) {
      userPlans.push(p);
    }
  }
  return userPlans.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
}

/**
 * Retrieves a single travel plan by ID, strictly verifying user ownership.
 */
export async function getUserTravelPlanById(planId: string, userId: string): Promise<TravelPlanRecord | null> {
  if (process.env.DATABASE_URL) {
    try {
      const query = `
        SELECT id, user_id, destination, number_of_days, budget_inr, number_of_travellers, interests, accommodation_preference, activity_level, additional_notes, plan_data, created_at, updated_at
        FROM travel_plans
        WHERE id = $1 AND user_id = $2;
      `;
      const result = await pool.query(query, [planId, userId]);
      if (result.rows.length > 0) {
        return result.rows[0];
      }
      return null;
    } catch (err) {
      console.error('[DB] Error retrieving user travel plan by ID from PostgreSQL:', err instanceof Error ? err.message : err);
    }
  }

  // Fallback in-memory retrieval
  const plan = inMemoryPlans.get(planId);
  if (plan && plan.user_id === userId) {
    return plan;
  }
  return null;
}
