-- TemanTumbuh: manajemen Guru BK dan siswa untuk Admin
-- Jalankan di Supabase SQL Editor setelah meninjau backup/schema.
-- Tidak menghapus akun, relasi, progres, evaluasi, atau pesan.

alter table public.profiles
  add column if not exists account_status text not null default 'active';

alter table public.profiles
  drop constraint if exists profiles_account_status_check;
alter table public.profiles
  add constraint profiles_account_status_check
  check (account_status in ('active','inactive'));

create index if not exists profiles_role_approval_status_idx
  on public.profiles (role, approval_status);
create index if not exists profiles_teacher_id_idx
  on public.profiles (teacher_id);

create or replace function public.admin_get_management_dashboard()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  result jsonb;
begin
  if not exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  ) then
    raise exception 'Akses ditolak: hanya admin yang dapat membuka manajemen akun.'
      using errcode = '42501';
  end if;

  select jsonb_build_object(
    'summary', jsonb_build_object(
      'teachers_total', (select count(*) from public.profiles where role='guru'),
      'students_total', (select count(*) from public.profiles where role='siswa'),
      'teachers_pending', (select count(*) from public.profiles where role='guru' and coalesce(approval_status,'pending')='pending'),
      'teachers_inactive', (select count(*) from public.profiles where role='guru' and approval_status='approved' and account_status='inactive')
    ),
    'pending_teachers', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',p.id,'full_name',p.full_name,'email',u.email,'created_at',p.created_at,
        'approval_status',p.approval_status,'invite_code',p.invite_code
      ) order by p.created_at desc)
      from public.profiles p left join auth.users u on u.id=p.id
      where p.role='guru' and coalesce(p.approval_status,'pending')='pending'
    ), '[]'::jsonb),
    'approved_teachers', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',p.id,'full_name',p.full_name,'email',u.email,'created_at',p.created_at,
        'invite_code',p.invite_code,'account_status',p.account_status
      ) order by p.full_name)
      from public.profiles p left join auth.users u on u.id=p.id
      where p.role='guru' and p.approval_status='approved' and p.account_status='active'
    ), '[]'::jsonb),
    'inactive_teachers', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',p.id,'full_name',p.full_name,'email',u.email,'created_at',p.created_at,
        'invite_code',p.invite_code,'account_status',p.account_status
      ) order by p.full_name)
      from public.profiles p left join auth.users u on u.id=p.id
      where p.role='guru' and p.approval_status='approved' and p.account_status='inactive'
    ), '[]'::jsonb),
    'rejected_teachers', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',p.id,'full_name',p.full_name,'email',u.email,'created_at',p.created_at,
        'invite_code',p.invite_code,'approval_status',p.approval_status
      ) order by p.created_at desc)
      from public.profiles p left join auth.users u on u.id=p.id
      where p.role='guru' and p.approval_status='rejected'
    ), '[]'::jsonb),
    'students', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id',s.id,'full_name',s.full_name,'email',u.email,'created_at',s.created_at,
        'teacher_id',s.teacher_id,'teacher_name',t.full_name,'teacher_invite_code',t.invite_code
      ) order by t.full_name nulls last, s.full_name)
      from public.profiles s
      left join auth.users u on u.id=s.id
      left join public.profiles t on t.id=s.teacher_id and t.role='guru'
      where s.role='siswa'
    ), '[]'::jsonb)
  ) into result;

  return result;
end;
$$;

create or replace function public.admin_set_teacher_active(
  p_teacher_id uuid,
  p_is_active boolean
)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  ) then
    raise exception 'Akses ditolak: hanya admin yang dapat mengubah status Guru BK.'
      using errcode = '42501';
  end if;

  update public.profiles
  set account_status = case when p_is_active then 'active' else 'inactive' end
  where id = p_teacher_id
    and role = 'guru'
    and approval_status = 'approved';

  if not found then
    raise exception 'Guru BK tidak ditemukan atau belum disetujui.';
  end if;
end;
$$;

revoke all on function public.admin_get_management_dashboard() from public;
revoke all on function public.admin_set_teacher_active(uuid, boolean) from public;
grant execute on function public.admin_get_management_dashboard() to authenticated;
grant execute on function public.admin_set_teacher_active(uuid, boolean) to authenticated;

-- Catatan keamanan:
-- Fungsi admin di atas membatasi data dashboard dan perubahan status ke role admin.
-- Agar akun nonaktif benar-benar tidak dapat memakai API langsung, kebijakan RLS
-- pada tabel-tabel data Guru BK juga harus memeriksa profiles.account_status='active'.
-- Audit kebijakan RLS aplikasi yang sudah ada sebelum menambahkan/mengubah policy,
-- supaya akses siswa, chat, progres, dan evaluasi tidak terputus.
