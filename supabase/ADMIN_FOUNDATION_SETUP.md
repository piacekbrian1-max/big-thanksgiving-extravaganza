# RoamSonio Admin Foundation — Phase 2A

This phase adds the secure foundation for multiple administrator levels and approval-based changes.

## Roles
- support_admin — level 10
- admin — level 20
- senior_admin — level 30
- master_admin — level 100

Only one active master admin is allowed by the bootstrap function.

## What is protected
The database, not the browser UI, controls:
- who has an administrator role
- who can submit an approval request
- who can review an approval
- the minimum approval level
- prevention of self-approval
- administrator audit history

Do not use user_metadata for authorization.

## Apply the migration
1. Open the RoamSonio Supabase project.
2. Open the SQL Editor.
3. Run the complete migration: supabase/migrations/20261003_roamsonio_admin_foundation.sql
4. Find the UUID of the RoamSonio owner account in auth.users.
5. Run the bootstrap function manually, replacing the placeholder UUID:

    select public.roamsonio_bootstrap_master_admin('YOUR-AUTH-USER-UUID');

The bootstrap function refuses to create a second active Master Admin.

## Important
This migration intentionally does NOT modify the existing users, trips, families, or application records.
It also does not automatically apply proposed business-data changes after approval. That is intentional. Phase 2B will add dedicated, validated approval/apply RPCs for each type of change.

## Next test
After the migration and bootstrap are complete, the next implementation step is to update the Master Account page so it reads its role from the protected database function rather than relying on client-visible role metadata.

Then we will test:
1. normal user → no Master Account access
2. support admin → limited admin access
3. admin → broader access
4. senior admin → approval access
5. master admin → full access
6. requester → cannot approve their own request
7. lower-level admin → cannot approve a request requiring a higher level
8. master admin → remains the final authority

Only after those tests pass will real cross-user/trip data be connected.