-- RoamSonio account-transfer safety audit: schema inventory ONLY
-- This migration does NOT modify any application data.
-- Run the SELECT statements in Supabase SQL Editor and send the results back.
-- We will use the results to design the transfer RPC without guessing schema.

-- 1) All public tables.
select
  table_schema,
  table_name
from information_schema.tables
where table_schema = 'public'
  and table_type = 'BASE TABLE'
order by table_name;

-- 2) Columns that can identify an account/user/owner/member/recipient.
select
  table_name,
  column_name,
  data_type,
  udt_name,
  is_nullable
from information_schema.columns
where table_schema = 'public'
  and (
    column_name ilike '%user%'
    or column_name ilike '%owner%'
    or column_name ilike '%member%'
    or column_name ilike '%recipient%'
    or column_name ilike '%sender%'
    or column_name ilike '%created_by%'
    or column_name ilike '%assigned%'
  )
order by table_name, ordinal_position;

-- 3) Foreign keys in public tables, so we can see exactly what references auth.users
-- and what could be affected by an account transfer.
select
  tc.table_name,
  kcu.column_name,
  ccu.table_schema as foreign_table_schema,
  ccu.table_name as foreign_table_name,
  ccu.column_name as foreign_column_name,
  rc.delete_rule,
  rc.update_rule
from information_schema.table_constraints tc
join information_schema.key_column_usage kcu
  on tc.constraint_name = kcu.constraint_name
 and tc.table_schema = kcu.table_schema
join information_schema.constraint_column_usage ccu
  on tc.constraint_name = ccu.constraint_name
 and tc.table_schema = ccu.table_schema
join information_schema.referential_constraints rc
  on tc.constraint_name = rc.constraint_name
 and tc.constraint_schema = rc.constraint_schema
where tc.table_schema = 'public'
  and tc.constraint_type = 'FOREIGN KEY'
order by tc.table_name, kcu.column_name;

-- 4) Existing functions whose names suggest ownership/account/trip/family/sharing.
select
  routine_name,
  routine_type
from information_schema.routines
where routine_schema = 'public'
  and (
    routine_name ilike '%trip%'
    or routine_name ilike '%family%'
    or routine_name ilike '%share%'
    or routine_name ilike '%account%'
    or routine_name ilike '%user%'
  )
order by routine_name;
