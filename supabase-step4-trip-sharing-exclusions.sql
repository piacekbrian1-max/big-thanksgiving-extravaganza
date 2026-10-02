-- RoamSonio trip sharing: per-member family exclusions
-- Run this after supabase-step3-trip-sharing.sql

alter table public.trip_shares
  add column if not exists excluded_member_ids uuid[] not null default '{}';

create or replace function public.get_trip_share(share_token uuid)
returns table (trip_name text, snapshot jsonb, access_type text, permission text, expires_at timestamptz)
language plpgsql security definer set search_path = public stable
as $$
declare s public.trip_shares%rowtype;
begin
  select * into s from public.trip_shares where public.trip_shares.share_token = get_trip_share.share_token;
  if not found then raise exception 'This shared trip could not be found.'; end if;
  if s.revoked_at is not null then raise exception 'This shared trip has been revoked.'; end if;
  if s.expires_at is not null and s.expires_at < now() then raise exception 'This shared trip link has expired.'; end if;
  if s.access_type = 'family' then
    if auth.uid() is null then raise exception 'Sign in to view this family trip.'; end if;
    if not exists (
      select 1 from public.family_members fm
      where fm.family_id=s.family_id and fm.user_id=auth.uid() and fm.status='active'
    ) then
      raise exception 'You are not a member of this family.'; 
    end if;
    if auth.uid() = any(coalesce(s.excluded_member_ids, '{}')) then
      raise exception 'This trip was not shared with you.';
    end if;
  end if;
  return query select s.trip_name,s.snapshot,s.access_type,s.permission,s.expires_at;
end;
$$;

revoke all on function public.get_trip_share(uuid) from public;
grant execute on function public.get_trip_share(uuid) to anon, authenticated;