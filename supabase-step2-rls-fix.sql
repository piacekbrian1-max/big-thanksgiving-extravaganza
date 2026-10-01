-- RoamSonio Step 2A RLS fix
-- Fixes the recursive family_members policy encountered during family creation.

create or replace function public.is_family_owner(target_family_id uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.families
    where id = target_family_id
      and owner_id = auth.uid()
  );
$$;

revoke all on function public.is_family_owner(uuid) from public;
grant execute on function public.is_family_owner(uuid) to authenticated;

drop policy if exists "family members can read family" on public.families;
create policy "family members can read family"
on public.families for select
using (
  owner_id = auth.uid()
  or exists (
    select 1 from public.family_members fm
    where fm.family_id = families.id
      and fm.user_id = auth.uid()
      and fm.status = 'active'
  )
);

drop policy if exists "members can read membership" on public.family_members;
create policy "members can read membership"
on public.family_members for select
using (
  user_id = auth.uid()
  or public.is_family_owner(family_id)
);

drop policy if exists "owners can add membership" on public.family_members;
create policy "owners can add membership"
on public.family_members for insert
with check (
  public.is_family_owner(family_id)
);

drop policy if exists "members can read invitations" on public.family_invitations;
create policy "members can read invitations"
on public.family_invitations for select
using (
  invited_by = auth.uid()
  or public.is_family_owner(family_id)
  or exists (
    select 1 from public.family_members fm
    where fm.family_id = family_invitations.family_id
      and fm.user_id = auth.uid()
      and fm.status = 'active'
  )
);

drop policy if exists "members can create invitations" on public.family_invitations;
create policy "members can create invitations"
on public.family_invitations for insert
with check (
  invited_by = auth.uid()
  and (
    public.is_family_owner(family_id)
    or exists (
      select 1 from public.family_members fm
      where fm.family_id = family_invitations.family_id
        and fm.user_id = auth.uid()
        and fm.status = 'active'
    )
  )
);
