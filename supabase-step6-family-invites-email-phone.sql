-- RoamSonio: email OR mobile family invitations
-- Run in Supabase SQL Editor before testing the updated invitation form.

alter table public.family_invitations
  add column if not exists phone text;

create or replace function public.create_family_invitation(
  p_family_id uuid,
  p_email text,
  p_phone text,
  p_role text
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

  if nullif(trim(coalesce(p_email,'')),'') is null
     and nullif(trim(coalesce(p_phone,'')),'') is null then
    raise exception 'Enter an email address, a mobile number, or both.';
  end if;

  if p_role not in ('adult','member','guest') then
    raise exception 'Choose a valid family role.';
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
    family_id, invited_by, email, phone, role
  )
  values (
    p_family_id,
    auth.uid(),
    nullif(lower(trim(coalesce(p_email,''))),''),
    nullif(trim(coalesce(p_phone,'')),''),
    p_role
  )
  returning * into inv;

  return query select inv.invite_token, inv.expires_at;
end;
$$;

revoke all on function public.create_family_invitation(uuid,text,text,text) from public;
grant execute on function public.create_family_invitation(uuid,text,text,text) to authenticated;
