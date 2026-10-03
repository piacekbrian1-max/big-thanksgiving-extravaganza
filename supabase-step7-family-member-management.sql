-- RoamSonio: family member management
-- Run after the named-invitation SQL.

create or replace function public.manage_family_member(
  p_family_id uuid,
  p_user_id uuid,
  p_action text,
  p_role text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in to manage family members.';
  end if;

  if not exists (
    select 1
    from public.family_members
    where family_id = p_family_id
      and user_id = auth.uid()
      and role = 'owner'
      and status = 'active'
  ) then
    raise exception 'Only the Family Owner can manage family members.';
  end if;

  if p_user_id = auth.uid() then
    raise exception 'The Family Owner cannot manage their own membership here.';
  end if;

  if not exists (
    select 1
    from public.family_members
    where family_id = p_family_id
      and user_id = p_user_id
      and status = 'active'
  ) then
    raise exception 'Family member not found.';
  end if;

  if p_action = 'role' then
    if p_role not in ('adult','member','guest') then
      raise exception 'Choose a valid family role.';
    end if;

    update public.family_members
    set role = p_role
    where family_id = p_family_id
      and user_id = p_user_id
      and status = 'active';

  elsif p_action = 'remove' then
    update public.family_members
    set status = 'removed'
    where family_id = p_family_id
      and user_id = p_user_id
      and status = 'active';

  else
    raise exception 'Unknown family management action.';
  end if;
end;
$$;

revoke all on function public.manage_family_member(uuid,uuid,text,text) from public;
grant execute on function public.manage_family_member(uuid,uuid,text,text) to authenticated;

create or replace function public.manage_family_invitation(
  p_family_id uuid,
  p_invite_token uuid,
  p_action text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in to manage invitations.';
  end if;

  if not exists (
    select 1
    from public.family_members
    where family_id = p_family_id
      and user_id = auth.uid()
      and role = 'owner'
      and status = 'active'
  ) then
    raise exception 'Only the Family Owner can manage invitations.';
  end if;

  if p_action = 'revoke' then
    update public.family_invitations
    set status = 'revoked'
    where family_id = p_family_id
      and invite_token = p_invite_token
      and status = 'pending';
  else
    raise exception 'Unknown invitation management action.';
  end if;
end;
$$;

revoke all on function public.manage_family_invitation(uuid,uuid,text) from public;
grant execute on function public.manage_family_invitation(uuid,uuid,text) to authenticated;
