-- RoamSonio Step 2B: invitation helpers
-- Run this in Supabase SQL Editor before testing invitations.

create or replace function public.get_family_invite(invite_token uuid)
returns table (
  family_name text,
  role text,
  status text,
  expires_at timestamptz,
  invited_by text
)
language sql
security definer
set search_path = public
stable
as $
  select
    f.name,
    i.role,
    i.status,
    i.expires_at,
    coalesce(nullif(fm.display_name,''),'Family Owner')
  from public.family_invitations i
  join public.families f on f.id = i.family_id
  left join public.family_members fm
    on fm.family_id = i.family_id
   and fm.user_id = f.owner_id
   and fm.role = 'owner'
   and fm.status = 'active'
  where i.invite_token = get_family_invite.invite_token;
$;

revoke all on function public.get_family_invite(uuid) from public;
grant execute on function public.get_family_invite(uuid) to anon, authenticated;

create or replace function public.accept_family_invite(invite_token uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  invite public.family_invitations%rowtype;
begin
  if auth.uid() is null then
    raise exception 'You must be signed in to accept a family invitation.';
  end if;

  select * into invite
  from public.family_invitations
  where public.family_invitations.invite_token = accept_family_invite.invite_token
  for update;

  if not found then
    raise exception 'Invitation not found.';
  end if;

  if invite.status <> 'pending' then
    raise exception 'This invitation is no longer pending.';
  end if;

  if invite.expires_at < now() then
    update public.family_invitations set status = 'revoked' where id = invite.id;
    raise exception 'This invitation has expired.';
  end if;

  insert into public.family_members (family_id, user_id, role, status)
  values (invite.family_id, auth.uid(), invite.role, 'active')
  on conflict (family_id, user_id)
  do update set role = excluded.role, status = 'active';

  update public.family_invitations
  set status = 'accepted'
  where id = invite.id;

  return invite.family_id::text;
end;
$$;

revoke all on function public.accept_family_invite(uuid) from public;
grant execute on function public.accept_family_invite(uuid) to authenticated;
