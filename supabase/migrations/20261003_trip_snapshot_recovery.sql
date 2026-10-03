-- Store a durable snapshot of the user-facing trip so account-backed trips can be recovered
-- from browser localStorage and inspected by Master Admin without depending on one device.
alter table public.trips
  add column if not exists trip_snapshot jsonb;

comment on column public.trips.trip_snapshot is
  'Durable RoamSonio trip snapshot used for recovery, workspace continuity, and protected Master Admin read-only visibility.';

