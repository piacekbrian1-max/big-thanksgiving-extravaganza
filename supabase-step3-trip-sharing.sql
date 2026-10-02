-- RoamSonio trip sharing foundation
create table if not exists public.trip_shares (
  id uuid primary key default gen_random_uuid(),
  trip_id text not null,
  owner_id uuid not null references auth.users(id) on delete cascade,
  family_id uuid references public.families(id) on delete cascade,
  access_type text not null check (access_type in ('link','family')),
  permission text not null default 'view' check (permission in ('view')),
  share_token uuid not null default gen_random_uuid() unique,
  trip_name text not null,
  snapshot jsonb not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz
);

alter table public.trip_shares enable row level security;

drop policy if exists "owners can read trip shares" on public.trip_shares;
create policy "owners can read trip shares" on public.trip_shares for select using (owner_id = auth.uid());

drop policy if exists "owners can create trip shares" on public.trip_shares;
create policy "owners can create trip shares" on public.trip_shares for insert with check (owner_id = auth.uid());

drop policy if exists "owners can update trip shares" on public.trip_shares;
create policy "owners can update trip shares" on public.trip_shares for update using (owner_id = auth.uid()) with check (owner_id = auth.uid());

drop policy if exists "owners can delete trip shares" on public.trip_shares;
create policy "owners can delete trip shares" on public.trip_shares for delete using (owner_id = auth.uid());

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
    if not exists (select 1 from public.family_members fm where fm.family_id=s.family_id and fm.user_id=auth.uid() and fm.status='active') then
      raise exception 'You are not a member of this family.'; end if;
  end if;
  return query select s.trip_name,s.snapshot,s.access_type,s.permission,s.expires_at;
end;
$$;
revoke all on function public.get_trip_share(uuid) from public;
grant execute on function public.get_trip_share(uuid) to anon, authenticated;