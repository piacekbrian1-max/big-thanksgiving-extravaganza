-- RoamSonio Step 2: family foundation
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.families (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.family_members (
  family_id uuid not null references public.families(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','adult','member','guest')),
  status text not null default 'active' check (status in ('active','pending')),
  created_at timestamptz not null default now(),
  primary key (family_id,user_id)
);

create table if not exists public.family_invitations (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.families(id) on delete cascade,
  invited_by uuid not null references auth.users(id) on delete cascade,
  email text,
  invite_token uuid not null default gen_random_uuid() unique,
  role text not null default 'member' check (role in ('adult','member','guest')),
  status text not null default 'pending' check (status in ('pending','accepted','declined','revoked')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '14 days')
);

alter table public.profiles enable row level security;
alter table public.families enable row level security;
alter table public.family_members enable row level security;
alter table public.family_invitations enable row level security;

drop policy if exists "profiles own read" on public.profiles;
create policy "profiles own read" on public.profiles for select using (id = auth.uid());
drop policy if exists "profiles own insert" on public.profiles;
create policy "profiles own insert" on public.profiles for insert with check (id = auth.uid());
drop policy if exists "profiles own update" on public.profiles;
create policy "profiles own update" on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "family members can read family" on public.families;
create policy "family members can read family" on public.families for select using (
  owner_id = auth.uid() or exists (
    select 1 from public.family_members fm
    where fm.family_id = families.id and fm.user_id = auth.uid() and fm.status = 'active'
  )
);
drop policy if exists "users can create families" on public.families;
create policy "users can create families" on public.families for insert with check (owner_id = auth.uid());
drop policy if exists "owners can update families" on public.families;
create policy "owners can update families" on public.families for update using (owner_id = auth.uid()) with check (owner_id = auth.uid());

drop policy if exists "members can read membership" on public.family_members;
create policy "members can read membership" on public.family_members for select using (
  user_id = auth.uid() or exists (
    select 1 from public.family_members mine
    where mine.family_id = family_members.family_id and mine.user_id = auth.uid() and mine.status = 'active'
  )
);
drop policy if exists "owners can add membership" on public.family_members;
create policy "owners can add membership" on public.family_members for insert with check (
  exists (select 1 from public.families f where f.id = family_id and f.owner_id = auth.uid())
);

drop policy if exists "members can read invitations" on public.family_invitations;
create policy "members can read invitations" on public.family_invitations for select using (
  invited_by = auth.uid() or exists (
    select 1 from public.family_members fm
    where fm.family_id = family_invitations.family_id and fm.user_id = auth.uid() and fm.status = 'active'
  )
);
drop policy if exists "members can create invitations" on public.family_invitations;
create policy "members can create invitations" on public.family_invitations for insert with check (
  invited_by = auth.uid() and exists (
    select 1 from public.family_members fm
    where fm.family_id = family_invitations.family_id and fm.user_id = auth.uid() and fm.status = 'active'
  )
);
