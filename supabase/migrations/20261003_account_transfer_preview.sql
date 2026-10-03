-- RoamSonio Account Transfer: read-only preview foundation
-- IMPORTANT: This migration does NOT modify application data.
-- It creates a protected preview RPC only.
-- Requires Phase 2A/2B foundations.

create or replace function public.roamsonio_preview_account_transfer(
  p_source_user_id uuid,
  p_target_user_id uuid
)
returns table(
  action text,
  record_type text,
  record_id text,
  record_name text,
  source_user_id uuid,
  target_user_id uuid,
  detail text
)
language plpgsql
security definer
set search_path = ''
stable
as $$
declare
  v_source_exists boolean;
  v_target_exists boolean;
  v_target_admin boolean;
begin
  if auth.uid() is null
     or not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;

  if p_source_user_id is null or p_target_user_id is null then
    raise exception 'Source and target user IDs are required';
  end if;

  if p_source_user_id <> auth.uid() then
    raise exception 'The source account must be the currently authenticated Master Admin';
  end if;

  if p_source_user_id = p_target_user_id then
    raise exception 'Source and target accounts must be different';
  end if;

  select exists(
    select 1 from auth.users where id=p_source_user_id
  ) into v_source_exists;

  select exists(
    select 1 from auth.users where id=p_target_user_id
  ) into v_target_exists;

  if not v_source_exists then
    raise exception 'Source account not found';
  end if;

  if not v_target_exists then
    raise exception 'Target account not found';
  end if;

  select exists(
    select 1
    from public.roamsonio_admin_roles
    where user_id=p_target_user_id
      and active=true
  ) into v_target_admin;

  if v_target_admin then
    raise exception 'Target account has an active admin role and cannot be a normal-account transfer target';
  end if;

  -- Family ownership: transfer owner only; preserve family ID and history.
  return query
  select
    'TRANSFER_OWNER'::text,
    'family'::text,
    f.id::text,
    f.name::text,
    p_source_user_id,
    p_target_user_id,
    'families.owner_id will move; family ID and created_at remain unchanged'::text
  from public.families f
  where f.owner_id=p_source_user_id;

  -- Family membership: transfer the existing owner membership to the new user.
  return query
  select
    'TRANSFER_USER'::text,
    'family_member'::text,
    fm.family_id::text,
    f.name::text,
    p_source_user_id,
    p_target_user_id,
    ('preserve role=' || fm.role || ' and status=' || fm.status)::text
  from public.family_members fm
  join public.families f on f.id=fm.family_id
  where fm.user_id=p_source_user_id;

  -- Trips: transfer ownership by immutable trip UUID.
  return query
  select
    'TRANSFER_OWNER'::text,
    'trip'::text,
    t.id::text,
    t.name::text,
    p_source_user_id,
    p_target_user_id,
    ('visibility=' || t.visibility ||
     ' | family_id=' || coalesce(t.family_id::text,'NULL'))::text
  from public.trips t
  where t.owner_id=p_source_user_id;

  -- Trip shares: transfer share ownership only. Never rewrite trip_id/token/snapshot.
  return query
  select
    'TRANSFER_OWNER'::text,
    'trip_share'::text,
    ts.id::text,
    ts.trip_name::text,
    p_source_user_id,
    p_target_user_id,
    ('access_type=' || ts.access_type ||
     ' | permission=' || ts.permission ||
     ' | family_id=' || coalesce(ts.family_id::text,'NULL') ||
     ' | revoked_at=' || coalesce(ts.revoked_at::text,'NULL'))::text
  from public.trip_shares ts
  where ts.owner_id=p_source_user_id;

  -- Invitations remain historically attributed to the account that actually sent them.
  return query
  select
    'KEEP'::text,
    'family_invitation'::text,
    fi.id::text,
    coalesce(fi.invitee_name,fi.email,'')::text,
    p_source_user_id,
    p_target_user_id,
    ('status=' || fi.status ||
     ' | email=' || coalesce(fi.email,'NULL') ||
     ' | family_id=' || fi.family_id::text)::text
  from public.family_invitations fi
  where fi.invited_by=p_source_user_id;

  -- Support requests, if any, follow the user as account history.
  return query
  select
    'TRANSFER_USER'::text,
    'support_request'::text,
    sr.id::text,
    sr.subject::text,
    p_source_user_id,
    p_target_user_id,
    ('status=' || sr.status || ' | priority=' || sr.priority)::text
  from public.roamsonio_support_requests sr
  where sr.user_id=p_source_user_id;

  -- Administrative role is explicitly protected and never transferred.
  return query
  select
    'KEEP'::text,
    'admin_role'::text,
    ar.user_id::text,
    ar.role::text,
    p_source_user_id,
    p_target_user_id,
    ('active=' || ar.active::text || ' | PROTECTED_ADMIN_DATA')::text
  from public.roamsonio_admin_roles ar
  where ar.user_id=p_source_user_id;

  -- Historical audit entries are immutable history and never rewritten.
  return query
  select
    'KEEP'::text,
    'admin_audit_actor'::text,
    al.id::text,
    al.action::text,
    p_source_user_id,
    p_target_user_id,
    'historical audit record remains attributed to original actor'::text
  from public.roamsonio_admin_audit_log al
  where al.actor_user_id=p_source_user_id;

  return query
  select
    'KEEP'::text,
    'admin_audit_target'::text,
    al.id::text,
    al.action::text,
    p_source_user_id,
    p_target_user_id,
    'historical audit record remains unchanged'::text
  from public.roamsonio_admin_audit_log al
  where al.target_user_id=p_source_user_id;
end;
$$;

revoke all on function public.roamsonio_preview_account_transfer(uuid,uuid)
  from public, anon, authenticated;

grant execute on function public.roamsonio_preview_account_transfer(uuid,uuid)
  to authenticated;
