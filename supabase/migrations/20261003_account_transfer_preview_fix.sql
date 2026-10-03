-- Fix RoamSonio account transfer preview.
-- READ-ONLY: replaces the preview function only.
-- No business data is modified.

create or replace function public.roamsonio_preview_account_transfer(
  p_source_user_id uuid,
  p_target_user_id uuid
)
returns table (
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
as $$
declare
  v_auth_user uuid;
  v_source_exists boolean;
  v_target_exists boolean;
  v_target_admin boolean;
  v_aal text;
begin
  v_auth_user := auth.uid();

  if v_auth_user is null then
    raise exception 'Authentication required';
  end if;

  if not public.roamsonio_is_master_admin() then
    raise exception 'Master Admin access required';
  end if;

  v_aal := coalesce((auth.jwt() ->> 'aal'), '');

  if v_aal <> 'aal2' then
    raise exception 'AAL2 / MFA required';
  end if;

  if p_source_user_id <> v_auth_user then
    raise exception 'Source user must be the authenticated Master Admin';
  end if;

  if p_source_user_id = p_target_user_id then
    raise exception 'Source and target accounts must be different';
  end if;

  select exists(
    select 1 from auth.users u where u.id = p_source_user_id
  ) into v_source_exists;

  if not v_source_exists then
    raise exception 'Source account does not exist';
  end if;

  select exists(
    select 1 from auth.users u where u.id = p_target_user_id
  ) into v_target_exists;

  if not v_target_exists then
    raise exception 'Target account does not exist';
  end if;

  -- IMPORTANT: the protected admin-role column is "active", not "is_active".
  select exists(
    select 1
    from public.roamsonio_admin_roles r
    where r.user_id = p_target_user_id
      and r.active = true
  ) into v_target_admin;

  if v_target_admin then
    raise exception 'Target account already has an active admin role';
  end if;

  return query
  select
    'TRANSFER_OWNER'::text,
    'family'::text,
    f.id::text,
    f.name::text,
    p_source_user_id,
    p_target_user_id,
    'Transfer family ownership; family ID remains unchanged'::text
  from public.families f
  where f.owner_id = p_source_user_id;

  return query
  select
    'TRANSFER_USER'::text,
    'family_member'::text,
    fm.family_id::text,
    null::text,
    p_source_user_id,
    p_target_user_id,
    (
      'Transfer membership; role='
      || coalesce(fm.role::text, '')
      || ', status='
      || coalesce(fm.status::text, '')
    )::text
  from public.family_members fm
  where fm.user_id = p_source_user_id;

  return query
  select
    'TRANSFER_OWNER'::text,
    'trip'::text,
    t.id::text,
    t.name::text,
    p_source_user_id,
    p_target_user_id,
    (
      'Transfer trip ownership; visibility='
      || coalesce(t.visibility::text, '')
      || ', family_id='
      || coalesce(t.family_id::text, 'NULL')
    )::text
  from public.trips t
  where t.owner_id = p_source_user_id;

  return query
  select
    'TRANSFER_OWNER'::text,
    'trip_share'::text,
    ts.id::text,
    ts.trip_name::text,
    p_source_user_id,
    p_target_user_id,
    (
      'Transfer share ownership only; preserve access_type='
      || coalesce(ts.access_type::text, '')
      || ', permission='
      || coalesce(ts.permission::text, '')
      || ', family_id='
      || coalesce(ts.family_id::text, 'NULL')
      || ', revoked_at='
      || coalesce(ts.revoked_at::text, 'NULL')
      || '; do NOT rewrite trip_id, share_token, or snapshot'
    )::text
  from public.trip_shares ts
  where ts.owner_id = p_source_user_id;

  return query
  select
    'KEEP'::text,
    'family_invitation'::text,
    fi.id::text,
    fi.invitee_name::text,
    p_source_user_id,
    p_target_user_id,
    'Historical invitation preserved; invited_by remains the original user'::text
  from public.family_invitations fi
  where fi.invited_by = p_source_user_id;

  return query
  select
    'TRANSFER_USER'::text,
    'support_request'::text,
    sr.id::text,
    sr.subject::text,
    p_source_user_id,
    p_target_user_id,
    'Transfer request ownership; assigned_to remains unchanged'::text
  from public.roamsonio_support_requests sr
  where sr.user_id = p_source_user_id;

  return query
  select
    'KEEP'::text,
    'admin_role'::text,
    r.user_id::text,
    r.role::text,
    p_source_user_id,
    p_target_user_id,
    'Master Admin role remains on the source account and is never transferred'::text
  from public.roamsonio_admin_roles r
  where r.user_id = p_source_user_id;

  return query
  select
    'KEEP'::text,
    'admin_audit_actor'::text,
    a.id::text,
    null::text,
    p_source_user_id,
    p_target_user_id,
    'Historical audit record preserved; actor_user_id is not rewritten'::text
  from public.roamsonio_admin_audit_log a
  where a.actor_user_id = p_source_user_id;

  return query
  select
    'KEEP'::text,
    'admin_audit_target'::text,
    a.id::text,
    null::text,
    p_source_user_id,
    p_target_user_id,
    'Historical audit record preserved; target_user_id is not rewritten'::text
  from public.roamsonio_admin_audit_log a
  where a.target_user_id = p_source_user_id;

end;
$$;

revoke all on function public.roamsonio_preview_account_transfer(uuid, uuid)
from public;

revoke all on function public.roamsonio_preview_account_transfer(uuid, uuid)
from anon;

revoke all on function public.roamsonio_preview_account_transfer(uuid, uuid)
from authenticated;

grant execute on function public.roamsonio_preview_account_transfer(uuid, uuid)
to authenticated;
