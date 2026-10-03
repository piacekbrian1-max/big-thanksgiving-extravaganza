-- RoamSonio: named family invitations with email and/or mobile

alter table public.family_invitations
  add column if not exists phone text;

alter table public.family_invitations
  add column if not exists invitee_name text;

alter table public.family_invitations
  alter column expires_at drop not null;

drop function if exists public.create_family_invitation(uuid,text,text,text);
drop function if exists public.create_family_invitation(uuid,text,text,text,text);

create function public.create_family_invitation(
  p_family_id uuid,
  p_invitee_name text,
  p_email text,
  p_phone text,
  p_role text,
  p_expiration text
)
returns table (invite_token uuid, expires_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  inv public.family_invitations%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Sign in to create a family invitation.';
  end if;

  if nullif(trim(coalesce(p_invitee_name,'')),'') is null then
    raise exception 'Enter the name of the person you are inviting.';
  end if;

  if nullif(trim(coalesce(p_email,'')),'') is null
     and nullif(trim(coalesce(p_phone,'')),'') is null then
    raise exception 'Enter an email address, a mobile number, or both.';
  end if;

  if p_role not in ('adult','member','guest') then
    raise exception 'Choose a valid family role.';
  end if;

  if p_expiration not in ('5','14','30','never') then
    raise exception 'Choose a valid invitation expiration.';
  end if;

  if not exists (
    select 1
    from public.family_members
    where family_id = p_family_id
      and user_id = auth.uid()
      and role = 'owner'
      and status = 'active'
  ) then
    raise exception 'Only the Family Owner can create invitations.';
  end if;

  insert into public.family_invitations (
    family_id, invited_by, invitee_name, email, phone, role
  )
  values (
    p_family_id,
    auth.uid(),
    trim(p_invitee_name),
    nullif(lower(trim(coalesce(p_email,''))),''),
    nullif(trim(coalesce(p_phone,'')),''),
    p_role
  )
  returning * into inv;

  return query select inv.invite_token, inv.expires_at;
end;
$$;

revoke all on function public.create_family_invitation(uuid,text,text,text,text,text) from public;
grant execute on function public.create_family_invitation(uuid,text,text,text,text,text) to authenticated;