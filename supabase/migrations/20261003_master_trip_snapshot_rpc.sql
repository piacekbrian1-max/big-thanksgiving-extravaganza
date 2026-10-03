-- Extend the protected Master Admin trip directory with durable trip snapshot details.
-- This is a follow-up migration so existing deployments do not need to replay prior migrations.

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
  select
    t.id,
    t.owner_id,
    u.email::text,
    coalesce(
      nullif(u.raw_user_meta_data->>'display_name',''),
      nullif(u.raw_user_meta_data->>'full_name',''),
      ''
    )::text,
    t.name::text,
    t.visibility::text,
    t.surprise_mode,
    t.created_at,
    nullif(t.trip_snapshot->>'start','')::date,
    nullif(t.trip_snapshot->>'end','')::date,
    coalesce(t.trip_snapshot->'destinations','[]'::jsonb),
    t.trip_snapshot
  from public.trips t
  left join auth.users u on u.id=t.owner_id
  order by t.created_at desc;
end;
$$;

revoke all on function public.roamsonio_admin_trips() from public,anon,authenticated;
grant execute on function public.roamsonio_admin_trips() to authenticated;
