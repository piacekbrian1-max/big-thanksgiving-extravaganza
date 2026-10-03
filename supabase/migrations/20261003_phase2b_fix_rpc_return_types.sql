-- Fix Phase 2B RPC return-type mismatches by explicitly casting database text/varchar values to text.

-- Read-only Master directory functions. These require both Master role and AAL2.
create or replace function public.roamsonio_admin_users()
returns table(
  user_id uuid,
  email text,
  display_name text,
  created_at timestamptz,
  last_sign_in_at timestamptz,
  email_confirmed_at timestamptz,
  admin_role text,
  admin_active boolean
)
language plpgsql
security definer
set search_path = ''
stable
as $$
begin
  if not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;
  return query
  select u.id,u.email::text,
    coalesce(nullif(u.raw_user_meta_data->>'display_name',''),
             nullif(u.raw_user_meta_data->>'full_name',''),'')::text,
    u.created_at,u.last_sign_in_at,u.email_confirmed_at,
    r.role::text,r.active
  from auth.users u
  left join public.roamsonio_admin_roles r on r.user_id=u.id
  order by u.created_at desc;
end;
$$;

create or replace function public.roamsonio_admin_trips()
returns table(
  trip_id uuid,
  owner_id uuid,
  owner_email text,
  owner_name text,
  trip_name text,
  visibility text,
  surprise_mode boolean,
  created_at timestamptz,
  start_date date,
  end_date date,
  destinations jsonb,
  trip_snapshot jsonb
)
language plpgsql
security definer
set search_path = ''
stable
as $$
begin
  if not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;
  return query
  select t.id,t.owner_id,u.email::text,
    coalesce(nullif(u.raw_user_meta_data->>'display_name',''),
             nullif(u.raw_user_meta_data->>'full_name',''),'')::text,
    t.name::text,t.visibility::text,t.surprise_mode,t.created_at,
    nullif(t.trip_snapshot->>'start','')::date,
    nullif(t.trip_snapshot->>'end','')::date,
    coalesce(t.trip_snapshot->'destinations','[]'::jsonb),
    t.trip_snapshot
  from public.trips t
  left join auth.users u on u.id=t.owner_id
  order by t.created_at desc;
end;
$$;

create or replace function public.roamsonio_admin_families()
returns table(
  family_id uuid,
  family_name text,
  owner_id uuid,
  owner_email text,
  owner_name text,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = ''
stable
as $$
begin
  if not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;
  return query
  select f.id,f.name::text,f.owner_id,u.email::text,
    coalesce(nullif(u.raw_user_meta_data->>'display_name',''),
             nullif(u.raw_user_meta_data->>'full_name',''),'')::text,
    f.created_at
  from public.families f
  left join auth.users u on u.id=f.owner_id
  order by f.created_at desc;
end;
$$;

create or replace function public.roamsonio_admin_support_requests()
returns table(
  request_id bigint,
  user_id uuid,
  user_email text,
  user_name text,
  subject text,
  category text,
  description text,
  priority text,
  status text,
  assigned_to uuid,
  admin_note text,
  created_at timestamptz,
  updated_at timestamptz
)
language plpgsql
security definer
set search_path = ''
stable
as $$
begin
  if not public.roamsonio_is_master_admin()
     or coalesce(auth.jwt()->>'aal','aal1') <> 'aal2' then
    raise exception 'Master Admin MFA verification required';
  end if;
  return query
  select s.id,s.user_id,u.email::text,
    coalesce(nullif(u.raw_user_meta_data->>'display_name',''),
             nullif(u.raw_user_meta_data->>'full_name',''),'')::text,
    s.subject::text,s.category::text,s.description::text,s.priority::text,s.status::text,s.assigned_to,
    s.admin_note::text,s.created_at,s.updated_at
  from public.roamsonio_support_requests s
  left join auth.users u on u.id=s.user_id
  order by s.created_at desc;
end;
$$;

revoke all on function public.roamsonio_admin_users() from public,anon,authenticated;
revoke all on function public.roamsonio_admin_trips() from public,anon,authenticated;
revoke all on function public.roamsonio_admin_families() from public,anon,authenticated;
revoke all on function public.roamsonio_admin_support_requests() from public,anon,authenticated;
grant execute on function public.roamsonio_admin_users() to authenticated;
grant execute on function public.roamsonio_admin_trips() to authenticated;
grant execute on function public.roamsonio_admin_families() to authenticated;
grant execute on function public.roamsonio_admin_support_requests() to authenticated;
