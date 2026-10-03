-- RoamSonio Master Admin activity feed
-- Read-only protected view of administrative audit history.

create or replace function public.roamsonio_admin_activity_log()
returns table(
  activity_id bigint,
  action text,
  actor_user_id uuid,
  actor_email text,
  target_user_id uuid,
  target_email text,
  approval_request_id bigint,
  details jsonb,
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
  select
    al.id,
    al.action::text,
    al.actor_user_id,
    actor.email::text,
    al.target_user_id,
    target.email::text,
    al.approval_request_id,
    al.details,
    al.created_at
  from public.roamsonio_admin_audit_log al
  left join auth.users actor on actor.id=al.actor_user_id
  left join auth.users target on target.id=al.target_user_id
  order by al.created_at desc
  limit 100;
end;
$$;

revoke all on function public.roamsonio_admin_activity_log() from public,anon,authenticated;
grant execute on function public.roamsonio_admin_activity_log() to authenticated;
