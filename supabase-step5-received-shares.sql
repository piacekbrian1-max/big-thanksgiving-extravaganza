-- RoamSonio: received shared trips library
-- Run after supabase-step4-trip-sharing-exclusions.sql

create or replace function public.get_received_trip_shares()
returns table (
  share_token uuid,
  trip_name text,
  snapshot jsonb,
  access_type text,
  permission text,
  created_at timestamptz,
  expires_at timestamptz
)
language plpgsql
security definer
set search_path = public
stable
as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in to view shared trips.';
  end if;

  return query
  select
    s.share_token,
    s.trip_name,
    s.snapshot,
    s.access_type,
    s.permission,
    s.created_at,
    s.expires_at
  from public.trip_shares s
  where s.access_type = 'family'
    and s.revoked_at is null
    and (s.expires_at is null or s.expires_at >= now())
    and s.owner_id <> auth.uid()
    and exists (
      select 1
      from public.family_members fm
      where fm.family_id = s.family_id
        and fm.user_id = auth.uid()
        and fm.status = 'active'
    )
    and not (auth.uid() = any(coalesce(s.excluded_member_ids, '{}')))
  order by s.created_at desc;
end;
$$;

revoke all on function public.get_received_trip_shares() from public;
grant execute on function public.get_received_trip_shares() to authenticated;
