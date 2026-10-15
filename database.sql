begin;

create table if not exists public.fasad_workspaces (
  id integer primary key check (id = 1),
  data jsonb not null check (jsonb_typeof(data) = 'object'),
  version integer not null check (version >= 0)
);
alter table public.fasad_workspaces enable row level security;
revoke all on table public.fasad_workspaces from public, anon, authenticated;
grant select, insert, update on table public.fasad_workspaces to service_role;

-- No client RLS policy: only the authenticated Edge Function reads this table.
-- Version checking and the mutation occur in one SQL statement, never in JS.
create or replace function public.fasad_write_state(expected_version integer, next_data jsonb)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare affected integer;
begin
  if next_data is null or jsonb_typeof(next_data) <> 'object' or expected_version < -1 then
    raise exception 'Invalid state';
  end if;
  if expected_version = -1 then
    insert into public.fasad_workspaces(id, data, version) values (1, next_data, 0)
      on conflict (id) do nothing;
  else
    update public.fasad_workspaces set data = next_data, version = version + 1
      where id = 1 and version = expected_version;
  end if;
  get diagnostics affected = row_count;
  return affected = 1;
end;
$$;
revoke all on function public.fasad_write_state(integer,jsonb) from public, anon, authenticated;
grant execute on function public.fasad_write_state(integer,jsonb) to service_role;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('fasad-photos','fasad-photos',false,4194304,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public=false,file_size_limit=excluded.file_size_limit,allowed_mime_types=excluded.allowed_mime_types;
-- A private bucket with no client policies is accessible only through our API.
-- Restrictive policy also protects it if this project already has broad policies.
drop policy if exists fasad_photos_server_only on storage.objects;
create policy fasad_photos_server_only on storage.objects as restrictive for all
to anon, authenticated
using (bucket_id <> 'fasad-photos') with check (bucket_id <> 'fasad-photos');
commit;
