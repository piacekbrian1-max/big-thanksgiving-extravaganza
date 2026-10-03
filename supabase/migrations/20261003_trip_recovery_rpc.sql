create or replace function public.roamsonio_recover_trip(
  p_name text,
  p_snapshot jsonb
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_id uuid;
begin
  if auth.uid() is null then
    raise exception 'You must be signed in to recover a trip';
  end if;

  if p_snapshot is null or jsonb_typeof(p_snapshot) <> 'object' then
    raise exception 'Trip snapshot is missing or invalid';
  end if;

  insert into public.trips(
    owner_id,
    name,
    visibility,
    surprise_mode,
    trip_snapshot
  )
  values(
    auth.uid(),
    coalesce(nullif(trim(p_name), ''), 'RoamSonio Trip'),
    'private',
    false,
    p_snapshot
  )
  returning id into new_id;

  return new_id;
end;
$$;

revoke all on function public.roamsonio_recover_trip(text, jsonb) from public;
grant execute on function public.roamsonio_recover_trip(text, jsonb) to authenticated;
