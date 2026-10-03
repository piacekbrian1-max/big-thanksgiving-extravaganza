-- RoamSonio generic account ownership transfer
-- Master Admin only, AAL2 required.
-- Supports transferring ownership/history for any eligible normal user to another
-- eligible normal user. It does not rewrite invitation authorship, admin roles,
-- immutable IDs, share tokens, snapshots, or historical audit actors.

create or replace function public.roamsonio_preview_user_transfer(
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
  v_source_admin boolean;
  v_target_admin boolean;
  v_source_families integer;
  v_source_memberships integer;
  v_source_trips integer;
  v_source_shares integer;
  v_source_support integer;
  v_target_families integer;
  v_target_trips integer;
  v_target_shares integer;
begin
  if auth.uid() is null
     or not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;

  if p_source_user_id is null or p_target_user_id is null then
    raise exception 'Source and target user IDs are required';
  end if;

  if p_source_user_id = p_target_user_id then
    raise exception 'Source and target accounts must be different';
  end if;

  select exists(select 1 from auth.users where id=p_source_user_id)
    into v_source_exists;
  select exists(select 1 from auth.users where id=p_target_user_id)
    into v_target_exists;

  if not v_source_exists then raise exception 'Source account not found'; end if;
  if not v_target_exists then raise exception 'Target account not found'; end if;

  select exists(
    select 1 from public.roamsonio_admin_roles
    where user_id=p_source_user_id and active=true
  ) into v_source_admin;

  select exists(
    select 1 from public.roamsonio_admin_roles
    where user_id=p_target_user_id and active=true
  ) into v_target_admin;

  if v_source_admin then
    raise exception 'Source account has an active admin role and is protected from normal account transfer';
  end if;

  if v_target_admin then
    raise exception 'Target account has an active admin role and cannot receive transferred ownership';
  end if;

  select count(*) into v_source_families from public.families where owner_id=p_source_user_id;
  select count(*) into v_source_memberships from public.family_members where user_id=p_source_user_id;
  select count(*) into v_source_trips from public.trips where owner_id=p_source_user_id;
  select count(*) into v_source_shares from public.trip_shares where owner_id=p_source_user_id;
  select count(*) into v_source_support from public.roamsonio_support_requests where user_id=p_source_user_id;

  select count(*) into v_target_families from public.families where owner_id=p_target_user_id;
  select count(*) into v_target_trips from public.trips where owner_id=p_target_user_id;
  select count(*) into v_target_shares from public.trip_shares where owner_id=p_target_user_id;

  if v_target_families > 0 or v_target_trips > 0 or v_target_shares > 0 then
    raise exception 'Target account already owns data and is not an empty transfer target';
  end if;

  if v_source_families > 0 then
    return query
    select 'TRANSFER_OWNER'::text,'family'::text,f.id::text,f.name::text,
      p_source_user_id,p_target_user_id,
      'Family ownership moves; family ID and timestamps remain unchanged'::text
    from public.families f where f.owner_id=p_source_user_id;
  end if;

  return query
  select 'TRANSFER_USER'::text,'family_member'::text,fm.family_id::text,
    coalesce(f.name,'')::text,p_source_user_id,p_target_user_id,
    ('preserve role='||fm.role||' and status='||fm.status)::text
  from public.family_members fm
  left join public.families f on f.id=fm.family_id
  where fm.user_id=p_source_user_id;

  return query
  select 'TRANSFER_OWNER'::text,'trip'::text,t.id::text,t.name::text,
    p_source_user_id,p_target_user_id,
    ('visibility='||t.visibility||' | family_id='||coalesce(t.family_id::text,'NULL'))::text
  from public.trips t where t.owner_id=p_source_user_id;

  return query
  select 'TRANSFER_OWNER'::text,'trip_share'::text,ts.id::text,ts.trip_name::text,
    p_source_user_id,p_target_user_id,
    ('access_type='||ts.access_type||' | permission='||ts.permission||
     ' | family_id='||coalesce(ts.family_id::text,'NULL')||
     ' | revoked_at='||coalesce(ts.revoked_at::text,'NULL'))::text
  from public.trip_shares ts where ts.owner_id=p_source_user_id;

  return query
  select 'TRANSFER_USER'::text,'support_request'::text,sr.id::text,sr.subject::text,
    p_source_user_id,p_target_user_id,
    ('status='||sr.status||' | priority='||sr.priority)::text
  from public.roamsonio_support_requests sr where sr.user_id=p_source_user_id;

  return query
  select 'KEEP'::text,'family_invitation'::text,fi.id::text,
    coalesce(fi.invitee_name,fi.email,'')::text,p_source_user_id,p_target_user_id,
    ('status='||fi.status||' | invited_by remains source | historical record preserved')::text
  from public.family_invitations fi where fi.invited_by=p_source_user_id;

  return query
  select 'KEEP'::text,'admin_audit_actor'::text,al.id::text,al.action::text,
    p_source_user_id,p_target_user_id,
    'Historical audit actor remains unchanged'::text
  from public.roamsonio_admin_audit_log al where al.actor_user_id=p_source_user_id;

  return query
  select 'KEEP'::text,'admin_audit_target'::text,al.id::text,al.action::text,
    p_source_user_id,p_target_user_id,
    'Historical audit target remains unchanged'::text
  from public.roamsonio_admin_audit_log al where al.target_user_id=p_source_user_id;
end;
$$;

create or replace function public.roamsonio_transfer_user_account(
  p_source_user_id uuid,
  p_target_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_source_exists boolean;
  v_target_exists boolean;
  v_source_admin boolean;
  v_target_admin boolean;
  v_source_families integer;
  v_source_memberships integer;
  v_source_trips integer;
  v_source_shares integer;
  v_source_support integer;
  v_target_families integer;
  v_target_trips integer;
  v_target_shares integer;
  v_transferred_memberships integer := 0;
begin
  if auth.uid() is null
     or not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;

  if p_source_user_id is null or p_target_user_id is null then
    raise exception 'Source and target user IDs are required';
  end if;
  if p_source_user_id = p_target_user_id then
    raise exception 'Source and target accounts must be different';
  end if;

  select exists(select 1 from auth.users where id=p_source_user_id) into v_source_exists;
  select exists(select 1 from auth.users where id=p_target_user_id) into v_target_exists;
  if not v_source_exists then raise exception 'Source account not found'; end if;
  if not v_target_exists then raise exception 'Target account not found'; end if;

  select exists(select 1 from public.roamsonio_admin_roles
    where user_id=p_source_user_id and active=true) into v_source_admin;
  select exists(select 1 from public.roamsonio_admin_roles
    where user_id=p_target_user_id and active=true) into v_target_admin;

  if v_source_admin then raise exception 'Source account has an active admin role and is protected'; end if;
  if v_target_admin then raise exception 'Target account has an active admin role and cannot receive transfer'; end if;

  select count(*) into v_source_families from public.families where owner_id=p_source_user_id;
  select count(*) into v_source_memberships from public.family_members where user_id=p_source_user_id;
  select count(*) into v_source_trips from public.trips where owner_id=p_source_user_id;
  select count(*) into v_source_shares from public.trip_shares where owner_id=p_source_user_id;
  select count(*) into v_source_support from public.roamsonio_support_requests where user_id=p_source_user_id;

  select count(*) into v_target_families from public.families where owner_id=p_target_user_id;
  select count(*) into v_target_trips from public.trips where owner_id=p_target_user_id;
  select count(*) into v_target_shares from public.trip_shares where owner_id=p_target_user_id;

  if v_target_families > 0 or v_target_trips > 0 or v_target_shares > 0 then
    raise exception 'Target account already owns data and is not an empty transfer target';
  end if;

  -- Prevent a primary-key collision if the target already belongs to a source family.
  if exists(
    select 1
    from public.family_members fm
    where fm.user_id=p_source_user_id
      and exists(
        select 1 from public.family_members fm2
        where fm2.family_id=fm.family_id and fm2.user_id=p_target_user_id
      )
  ) then
    raise exception 'Target account is already a member of one of the source account families';
  end if;

  update public.families set owner_id=p_target_user_id where owner_id=p_source_user_id;
  update public.family_members set user_id=p_target_user_id where user_id=p_source_user_id;
  get diagnostics v_transferred_memberships = row_count;
  update public.trips set owner_id=p_target_user_id where owner_id=p_source_user_id;
  update public.trip_shares set owner_id=p_target_user_id where owner_id=p_source_user_id;
  update public.roamsonio_support_requests set user_id=p_target_user_id where user_id=p_source_user_id;

  if exists(select 1 from public.families where owner_id=p_source_user_id)
     or exists(select 1 from public.family_members where user_id=p_source_user_id)
     or exists(select 1 from public.trips where owner_id=p_source_user_id)
     or exists(select 1 from public.trip_shares where owner_id=p_source_user_id)
     or exists(select 1 from public.roamsonio_support_requests where user_id=p_source_user_id) then
    raise exception 'Transfer verification failed; protected transaction rolled back';
  end if;

  insert into public.roamsonio_admin_audit_log(
    actor_user_id,action,target_user_id,details
  ) values (
    auth.uid(),'ACCOUNT_OWNERSHIP_TRANSFER',p_target_user_id,
    jsonb_build_object(
      'source_user_id',p_source_user_id,
      'target_user_id',p_target_user_id,
      'families_transferred',v_source_families,
      'family_memberships_transferred',v_source_memberships,
      'trips_transferred',v_source_trips,
      'trip_shares_transferred',v_source_shares,
      'support_requests_transferred',v_source_support,
      'family_invitations_changed',false,
      'admin_role_transferred',false,
      'historical_audit_records_changed',false
    )
  );

  return jsonb_build_object(
    'status','TRANSFER_COMPLETE',
    'source_user_id',p_source_user_id,
    'target_user_id',p_target_user_id,
    'families_transferred',v_source_families,
    'family_memberships_transferred',v_source_memberships,
    'trips_transferred',v_source_trips,
    'trip_shares_transferred',v_source_shares,
    'support_requests_transferred',v_source_support,
    'family_invitations_changed',false,
    'admin_role_transferred',false,
    'historical_audit_records_changed',false
  );
end;
$$;

revoke all on function public.roamsonio_preview_user_transfer(uuid,uuid) from public,anon,authenticated;
revoke all on function public.roamsonio_transfer_user_account(uuid,uuid) from public,anon,authenticated;
grant execute on function public.roamsonio_preview_user_transfer(uuid,uuid) to authenticated;
grant execute on function public.roamsonio_transfer_user_account(uuid,uuid) to authenticated;
