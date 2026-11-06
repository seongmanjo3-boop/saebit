-- =====================================================================
-- 새빛 사이트 데이터베이스 설정 (Supabase > SQL Editor 에 통째로 붙여넣고 Run)
-- 회원·등급·권한, 후원 승인, 후원회원, 공지사항·성명·논평·연구보고서·재정공개,
-- 자유게시판·책임회원 게시판·이사회 게시판과 댓글, 신고, 알림, 관리 기록, 삭제 요청,
-- 행사·교육 신청, 방문 통계, 소식지 구독, 대표이사 인사말, 파일 저장소와 보안 규칙.
-- 이전 버전을 이미 실행했어도 이 파일 전체를 다시 실행하면 됩니다(기존 데이터 유지).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1) 회원 정보
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9_]{4,20}$'),
  email text not null,
  is_admin boolean not null default false,
  agreed_privacy_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table public.profiles add column if not exists full_name text;
alter table public.profiles add column if not exists roles text[] not null default '{일반회원}';
alter table public.profiles add column if not exists perms text[] not null default '{}';
alter table public.profiles add column if not exists withdraw_requested_at timestamptz;
alter table public.profiles add column if not exists withdraw_reason text;
alter table public.profiles enable row level security;

-- 등급: 한 사람은 하나만, 대표이사와 이사회 의장만 함께 맡을 수 있음
create or replace function public.valid_roles(r text[]) returns boolean
language sql immutable as $$
  select r is not null and cardinality(r) between 1 and 2
     and r <@ array['일반회원','책임회원','이사','대표이사','이사회 의장']::text[]
     and (cardinality(r) = 1 or (r @> array['대표이사','이사회 의장']::text[]));
$$;
alter table public.profiles drop constraint if exists profiles_roles_check;
alter table public.profiles add constraint profiles_roles_check check (public.valid_roles(roles));

-- 권한: 관리자가 회원에게 나눠 주는 업무 권한
--   notice=공지사항 작성, statement=성명·논평 작성, report=연구보고서 올리기, finance=재정공개 자료 올리기,
--   event=행사·교육 관리, donation=후원 승인, board_free=자유게시판 관리, board_core=책임회원 게시판 관리,
--   withdraw=회원 탈퇴 승인, newsletter=소식지 구독자 관리
--   (게시판 관리: 남의 글·댓글 삭제. 책임회원 게시판 관리 권한은 그 게시판 열람도 포함)
create or replace function public.valid_perms(p text[]) returns boolean
language sql immutable as $$
  select p is not null and p <@ array['notice','statement','report','finance','event','donation','board_free','board_core','withdraw','newsletter']::text[];
$$;
alter table public.profiles drop constraint if exists profiles_perms_check;
-- 예전 '게시판 관리(board)' 권한은 두 게시판 관리 권한으로 나눠 옮김
update public.profiles
   set perms = (select coalesce(array_agg(distinct x), '{}') from unnest(array_remove(perms, 'board') || array['board_free','board_core']) x)
 where 'board' = any(perms);
alter table public.profiles add constraint profiles_perms_check check (public.valid_perms(perms));

-- 관리자 / 권한 / 등급 확인 함수
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;
create or replace function public.has_perm(p text) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin or p = any(perms) from public.profiles where id = auth.uid()), false);
$$;
create or replace function public.is_core() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin or roles && array['책임회원','이사','대표이사','이사회 의장']::text[]
                     from public.profiles where id = auth.uid()), false);
$$;
-- 책임회원 게시판을 볼 수 있는지: 책임회원 이상, 관리자, 책임회원 게시판 관리 권한자
create or replace function public.can_core_board() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_core() or public.has_perm('board_core');
$$;
create or replace function public.is_ceo() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select '대표이사' = any(roles) from public.profiles where id = auth.uid()), false);
$$;
-- 이사회 게시판을 볼 수 있는지: 이사·대표이사·이사회 의장, 관리자
create or replace function public.can_director_board() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin or roles && array['이사','대표이사','이사회 의장']::text[]
                     from public.profiles where id = auth.uid()), false);
$$;

-- ---------------------------------------------------------------------
-- 1-1) 알림 · 관리 기록 (여러 기능이 함께 씀)
--      알림과 관리 기록은 서버가 직접 남기며, 회원이 임의로 만들 수 없음
-- ---------------------------------------------------------------------
create table if not exists public.notifications (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  kind text not null,
  title text not null,
  link text,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_idx on public.notifications(user_id, created_at desc);
alter table public.notifications enable row level security;
drop policy if exists "notes_read_own" on public.notifications;
create policy "notes_read_own" on public.notifications for select to authenticated using (user_id = auth.uid());
drop policy if exists "notes_delete_own" on public.notifications;
create policy "notes_delete_own" on public.notifications for delete to authenticated using (user_id = auth.uid());

-- 알림이 생기면 화면에 바로 뜨도록 실시간(Realtime) 전송 대상에 추가
do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'notifications') then
    alter publication supabase_realtime add table public.notifications;
  end if;
end $$;

-- 읽음 표시 (ids 가 비어 있으면 모두 읽음)
create or replace function public.mark_notes_read(ids bigint[]) returns void
language sql security definer set search_path = public as $$
  update public.notifications set read_at = now()
   where user_id = auth.uid() and read_at is null and (ids is null or id = any(ids));
$$;
revoke all on function public.mark_notes_read(bigint[]) from public, anon;
grant execute on function public.mark_notes_read(bigint[]) to authenticated;

-- 한 사람에게 알림 보내기 (서버 내부용)
create or replace function public.notify(uid uuid, k text, t text, l text) returns void
language sql security definer set search_path = public as $$
  insert into public.notifications (user_id, kind, title, link)
  select uid, k, left(t, 200), l where exists (select 1 from public.profiles where id = uid);
$$;
-- 권한을 가진 사람(과 관리자) 모두에게 알림 보내기 (서버 내부용)
--   본인이 한 일이라도 처리할 일이면 본인에게도 알림 (예: 관리자가 직접 신고한 글)
create or replace function public.notify_perm(p text, k text, t text, l text) returns void
language sql security definer set search_path = public as $$
  insert into public.notifications (user_id, kind, title, link)
  select id, k, left(t, 200), l from public.profiles
   where (is_admin or p = any(perms));
$$;

-- 관리 기록: 누가 언제 무엇을 했는지 (관리자만 열람)
create table if not exists public.admin_logs (
  id bigint generated always as identity primary key,
  actor_id uuid,
  actor_name text,
  action text not null,
  target text,
  detail text,
  created_at timestamptz not null default now()
);
create index if not exists admin_logs_time_idx on public.admin_logs(created_at desc);
alter table public.admin_logs enable row level security;
drop policy if exists "logs_admin_read" on public.admin_logs;
create policy "logs_admin_read" on public.admin_logs for select to authenticated using (public.is_admin());

create or replace function public.log_action(a text, t text, d text) returns void
language sql security definer set search_path = public as $$
  insert into public.admin_logs (actor_id, actor_name, action, target, detail)
  select auth.uid(),
         coalesce((select coalesce(nullif(full_name, ''), username) || ' (' || username || ')'
                     from public.profiles where id = auth.uid()), '시스템'),
         a, left(t, 300), left(d, 500);
$$;
revoke all on function public.notify(uuid, text, text, text) from public, anon, authenticated;
revoke all on function public.notify_perm(text, text, text, text) from public, anon, authenticated;
revoke all on function public.log_action(text, text, text) from public, anon, authenticated;

-- 권한 이름 (관리 기록·알림 문구용)
create or replace function public.perm_label(p text) returns text
language sql immutable as $$
  select case p when 'notice' then '공지사항 작성' when 'statement' then '성명·논평 작성'
    when 'report' then '연구보고서 올리기' when 'finance' then '재정공개 자료 올리기'
    when 'event' then '행사·교육 관리' when 'donation' then '후원 승인'
    when 'board_free' then '자유게시판 관리' when 'board_core' then '책임회원 게시판 관리'
    when 'withdraw' then '회원 탈퇴 승인' when 'newsletter' then '소식지 구독자 관리' else p end;
$$;
create or replace function public.perms_text(p text[]) returns text
language sql immutable as $$
  select coalesce(nullif(array_to_string(array(select public.perm_label(x) from unnest(p) x), ', '), ''), '없음');
$$;
create or replace function public.won(n bigint) returns text
language sql immutable as $$ select to_char(n, 'FM999,999,999,999') || '원'; $$;

-- 가입하면 회원 정보 자동 생성
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username, email, full_name)
  values (new.id, lower(new.raw_user_meta_data->>'username'), new.email,
          left(trim(new.raw_user_meta_data->>'full_name'), 20));
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 아이디 중복 확인
create or replace function public.username_available(u text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.profiles where username = lower(u));
$$;
grant execute on function public.username_available(text) to anon, authenticated;

-- 이메일 중복 확인 (가입 화면, 비밀번호 찾기에서 사용)
create or replace function public.email_available(e text) returns boolean
language sql stable security definer set search_path = public, auth as $$
  select not exists (select 1 from auth.users where lower(email) = lower(trim(e)));
$$;
grant execute on function public.email_available(text) to anon, authenticated;

-- 아이디로 로그인: 아이디와 비밀번호가 맞을 때만 로그인용 이메일을 돌려줌
create or replace function public.login_email(u text, pw text) returns text
language plpgsql security definer set search_path = public, extensions, auth as $$
declare e text; h text;
begin
  select au.email, au.encrypted_password into e, h
    from auth.users au join public.profiles p on p.id = au.id
   where p.username = lower(trim(u));
  if e is null or h is null or pw is null then
    perform pg_sleep(0.3);
    return null;
  end if;
  if extensions.crypt(pw, h) = h then return e; end if;
  perform pg_sleep(0.3);
  return null;
end; $$;
revoke all on function public.login_email(text, text) from public;
grant execute on function public.login_email(text, text) to anon, authenticated;

-- 등급 변경 · 권한 부여 (관리자만)
create or replace function public.set_roles(target uuid, new_roles text[]) returns void
language plpgsql security definer set search_path = public as $$
declare old_r text[]; u text;
begin
  if not public.is_admin() then raise exception 'not_admin'; end if;
  if not public.valid_roles(new_roles) then raise exception 'invalid_roles'; end if;
  select roles, username into old_r, u from public.profiles where id = target;
  update public.profiles set roles = new_roles where id = target;
  if u is not null and old_r is distinct from new_roles then
    perform public.log_action('등급 변경', u, array_to_string(old_r, ' · ') || ' → ' || array_to_string(new_roles, ' · '));
    perform public.notify(target, 'role', '회원 등급이 ' || array_to_string(new_roles, ' · ') || '(으)로 바뀌었습니다', 'mypage');
    perform public.notify_perm('_admin_only', 'admin_change', '등급 변경: ' || u || ' → ' || array_to_string(new_roles, ' · '), 'admin');
  end if;
end; $$;
revoke all on function public.set_roles(uuid, text[]) from public;
grant execute on function public.set_roles(uuid, text[]) to authenticated;

create or replace function public.set_perms(target uuid, new_perms text[]) returns void
language plpgsql security definer set search_path = public as $$
declare old_p text[]; u text;
begin
  if not public.is_admin() then raise exception 'not_admin'; end if;
  if not public.valid_perms(new_perms) then raise exception 'invalid_perms'; end if;
  select perms, username into old_p, u from public.profiles where id = target;
  update public.profiles set perms = new_perms where id = target;
  if u is not null and old_p is distinct from new_perms then
    perform public.log_action('권한 변경', u, public.perms_text(old_p) || ' → ' || public.perms_text(new_perms));
    perform public.notify(target, 'perm', '업무 권한이 바뀌었습니다: ' || public.perms_text(new_perms), 'mypage');
    perform public.notify_perm('_admin_only', 'admin_change', '권한 변경: ' || u || ' → ' || public.perms_text(new_perms), 'admin');
  end if;
end; $$;
revoke all on function public.set_perms(uuid, text[]) from public;
grant execute on function public.set_perms(uuid, text[]) to authenticated;

-- 회원 정보 열람: 본인, 관리자, 후원 승인 권한자(후원자 이름 확인용)
drop policy if exists "profiles_read" on public.profiles;
create policy "profiles_read" on public.profiles for select
  using (id = auth.uid() or public.is_admin() or public.has_perm('donation') or public.has_perm('withdraw'));

-- ---------------------------------------------------------------------
-- 2) 후원 승인 요청
-- ---------------------------------------------------------------------
create table if not exists public.donations (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  kind text,
  amount integer not null check (amount >= 1000),
  photo_path text not null,
  memo text check (char_length(memo) <= 200),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  reject_reason text,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.donations alter column kind drop not null;
-- 탈퇴한 회원의 후원 기록은 재정 공개를 위해 남기되 누가 했는지는 지움
alter table public.donations alter column user_id drop not null;
alter table public.donations add column if not exists donor_ref uuid;  -- 탈퇴한 후원자를 익명으로 구분하는 값(후원자 수 집계용)
alter table public.donations drop constraint if exists donations_user_id_fkey;
alter table public.donations add constraint donations_user_id_fkey foreign key (user_id) references public.profiles(id) on delete set null;
alter table public.donations drop constraint if exists donations_kind_check;
alter table public.donations enable row level security;

drop policy if exists "donations_insert_own" on public.donations;
create policy "donations_insert_own" on public.donations for insert to authenticated
  with check (user_id = auth.uid() and status = 'pending' and reviewed_at is null and reject_reason is null);
drop policy if exists "donations_read" on public.donations;
create policy "donations_read" on public.donations for select
  using (user_id = auth.uid() or public.has_perm('donation'));
drop policy if exists "donations_admin_update" on public.donations;
create policy "donations_admin_update" on public.donations for update
  using (public.has_perm('donation')) with check (public.has_perm('donation'));

-- 후원 요청이 들어오면 담당자에게, 승인·거절되면 후원자에게 알림 + 관리 기록
create or replace function public.donations_after() returns trigger
language plpgsql security definer set search_path = public as $$
declare who text;
begin
  select username into who from public.profiles where id = new.user_id;
  if tg_op = 'INSERT' then
    perform public.notify_perm('donation', 'donation_new',
      '새 후원 승인 요청: ' || coalesce(who, '회원') || ' · ' || public.won(new.amount), 'admin');
    return new;
  end if;
  if new.status is distinct from old.status then
    perform public.log_action(case new.status when 'approved' then '후원 승인' when 'rejected' then '후원 거절' else '후원 대기로 되돌림' end,
      coalesce(who, '탈퇴한 회원'),
      public.won(new.amount) || case when new.status = 'rejected' and new.reject_reason is not null then ' · 사유: ' || new.reject_reason else '' end);
    if new.status in ('approved', 'rejected') then
      perform public.notify(new.user_id, 'donation_result',
        '후원 ' || public.won(new.amount) || '이 ' || case new.status when 'approved' then '승인되었습니다' else '거절되었습니다' end, 'mypage');
    end if;
  end if;
  return new;
end; $$;
drop trigger if exists donations_after on public.donations;
create trigger donations_after after insert or update on public.donations
  for each row execute function public.donations_after();

-- 후원회원: 승인된 후원 중 한 번에 3,000원 이상이 있거나,
--           한 달에 1,000원 이상 후원한 달이 3개월 이상 (한국 시간 기준 달)
create or replace function public.is_supporter(uid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.donations
                  where user_id = uid and status = 'approved' and amount >= 3000)
      or (select count(*) from (
            select date_trunc('month', created_at at time zone 'Asia/Seoul') m
              from public.donations where user_id = uid and status = 'approved'
             group by 1 having sum(amount) >= 1000) x) >= 3;
$$;

-- 게시판에 표시할 작성자 등급 문구 (예: "책임회원 · 후원")
create or replace function public.member_label(uid uuid) returns text
language sql stable security definer set search_path = public as $$
  select (select string_agg(x, ' · ' order by array_position(array['대표이사','이사회 의장','이사','책임회원','일반회원']::text[], x))
            from unnest(p.roles) x)
         || case when public.is_supporter(uid) then ' · 후원' else '' end
    from public.profiles p where p.id = uid;
$$;

-- 재정공개를 볼 수 있는지: 후원회원, 재정공개 권한자, 관리자
create or replace function public.can_finance() returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (public.has_perm('finance') or public.is_supporter(auth.uid()));
$$;

-- 재정공개 요약 (볼 수 있는 사람만)
create or replace function public.finance_summary() returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.can_finance() then raise exception 'permission denied'; end if;
  return json_build_object(
    'donors', (select count(distinct coalesce(user_id, donor_ref)) from public.donations where status = 'approved'),
    'new_this_year', (select count(*) from (
        select coalesce(user_id, donor_ref) d, min(created_at) first_at from public.donations
         where status = 'approved' and coalesce(user_id, donor_ref) is not null group by 1) f
       where date_trunc('year', f.first_at at time zone 'Asia/Seoul') = date_trunc('year', now() at time zone 'Asia/Seoul')),
    'count', (select count(*) from public.donations where status = 'approved'),
    'supporters', (select count(*) from public.profiles p where public.is_supporter(p.id)));
end; $$;
revoke all on function public.finance_summary() from public;
grant execute on function public.finance_summary() to authenticated;

-- 이체 확인 사진 저장소 (비공개: 본인과 후원 승인 권한자만)
insert into storage.buckets (id, name, public) values ('proofs', 'proofs', false)
  on conflict (id) do nothing;
drop policy if exists "proofs_upload_own" on storage.objects;
create policy "proofs_upload_own" on storage.objects for insert to authenticated
  with check (bucket_id = 'proofs' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "proofs_read" on storage.objects;
create policy "proofs_read" on storage.objects for select to authenticated
  using (bucket_id = 'proofs' and ((storage.foldername(name))[1] = auth.uid()::text or public.has_perm('donation') or public.has_perm('withdraw')));
drop policy if exists "proofs_delete" on storage.objects;
create policy "proofs_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'proofs' and (public.has_perm('withdraw') or public.has_perm('donation')));

-- ---------------------------------------------------------------------
-- 3) 공지사항 · 성명·논평 · 연구보고서 · 재정공개
--    notice·statement·report: 누구나 읽기 / finance: 후원회원 등만 읽기
--    쓰기: 관리자 또는 해당 권한(notice/statement/report/finance)을 받은 회원
--    수정: 권한자는 자기 글만, 관리자는 모든 글 / 삭제: 관리자만 (권한자는 '삭제 요청' → 관리자 승인)
-- ---------------------------------------------------------------------
create table if not exists public.posts (
  id bigint generated always as identity primary key,
  type text not null,
  title text not null check (char_length(title) between 1 and 200),
  body text,
  dept text,
  pinned boolean not null default false,
  file_path text,
  file_name text,
  file_size bigint,
  author_id uuid default auth.uid() references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);
-- 공지 첨부파일 내려받기 허용 여부 (끄면 화면에 내려받기 버튼이 나오지 않음)
alter table public.posts add column if not exists allow_download boolean not null default true;
alter table public.posts drop constraint if exists posts_type_check;
alter table public.posts add constraint posts_type_check check (type in ('notice','statement','report','finance'));
-- 성명·논평 구분
alter table public.posts add column if not exists category text;
alter table public.posts drop constraint if exists posts_category_check;
alter table public.posts add constraint posts_category_check check (category is null or (type = 'statement' and category in ('성명','논평')));
alter table public.posts enable row level security;

drop policy if exists "posts_read_all" on public.posts;
create policy "posts_read_all" on public.posts for select
  using (type <> 'finance' or public.can_finance());
drop policy if exists "posts_admin_insert" on public.posts;
create policy "posts_admin_insert" on public.posts for insert with check (public.has_perm(type));
drop policy if exists "posts_admin_update" on public.posts;
create policy "posts_admin_update" on public.posts for update
  using (public.has_perm(type) and author_id = auth.uid()) with check (public.has_perm(type) and author_id = auth.uid());
drop policy if exists "posts_admin_delete" on public.posts;
create policy "posts_admin_delete" on public.posts for delete using (public.is_admin());

-- 작성자 표시: 이름과 등급을 글을 쓸 때 서버가 직접 기록 (다른 사람 이름으로 쓰기 불가)
alter table public.posts add column if not exists author_name text;
alter table public.posts add column if not exists author_role text;
create or replace function public.posts_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
declare pr public.profiles;
begin
  if tg_op = 'INSERT' then
    select * into pr from public.profiles where id = auth.uid();
    new.author_id := auth.uid();
    new.author_name := coalesce(nullif(pr.full_name, ''), pr.username);
    new.author_role := public.member_label(auth.uid());
    new.created_at := now();
  else
    if current_setting('saebit.anonymize', true) = 'on' then return new; end if;
    new.author_id := old.author_id; new.author_name := old.author_name;
    new.author_role := old.author_role; new.created_at := old.created_at;
  end if;
  return new;
end; $$;
drop trigger if exists posts_stamp on public.posts;
create trigger posts_stamp before insert or update on public.posts
  for each row execute function public.posts_stamp();
-- 이미 올라온 글은 작성자 정보를 채워 넣음
alter table public.posts disable trigger posts_stamp;
update public.posts p set author_name = coalesce(nullif(pr.full_name, ''), pr.username), author_role = public.member_label(p.author_id)
  from public.profiles pr where pr.id = p.author_id and p.author_name is null;
alter table public.posts enable trigger posts_stamp;

-- 게시물을 지우면 관리 기록에 남김
create or replace function public.posts_after_delete() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.log_action('게시물 삭제',
    case old.type when 'notice' then '공지사항' when 'statement' then '성명·논평' when 'report' then '연구보고서' else '재정공개' end || ' · ' || old.title,
    '작성자 ' || coalesce(old.author_name, '-'));
  -- 관리자가 바로 지운 글에 걸려 있던 삭제 요청은 처리된 것으로 정리
  update public.delete_requests set status = 'approved', handled_at = now(),
         handled_by = coalesce((select coalesce(nullif(full_name, ''), username) || ' (' || username || ')' from public.profiles where id = auth.uid()), '관리자')
   where target_type = 'post' and target_id = old.id and status = 'pending';
  return old;
end; $$;
drop trigger if exists posts_after_delete on public.posts;
create trigger posts_after_delete after delete on public.posts
  for each row execute function public.posts_after_delete();

-- 새 공지·성명·논평·연구보고서가 올라오면 모든 회원에게 알림 (재정공개는 볼 수 있는 사람에게만, 쓴 사람 제외)
create or replace function public.posts_after_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.notifications (user_id, kind, title, link)
  select pr.id, 'new_' || new.type,
         case new.type when 'notice' then '새 공지사항' when 'statement' then '새 ' || coalesce(new.category, '성명')
                       when 'report' then '새 연구보고서' else '새 재정공개 자료' end || ': ' || left(new.title, 60),
         'post-' || new.id
    from public.profiles pr
   where pr.id is distinct from new.author_id
     and (new.type <> 'finance' or pr.is_admin or 'finance' = any(pr.perms) or public.is_supporter(pr.id));
  return new;
end; $$;
drop trigger if exists posts_after_insert on public.posts;
create trigger posts_after_insert after insert on public.posts
  for each row execute function public.posts_after_insert();

-- 공지·보고서 첨부파일 (공개 저장소)
insert into storage.buckets (id, name, public) values ('posts', 'posts', true)
  on conflict (id) do update set public = true;
-- 공개 저장소지만, 파일을 바꾸거나 지울 때 대상 파일을 찾을 수 있도록 읽기 규칙도 둠
drop policy if exists "posts_files_read" on storage.objects;
create policy "posts_files_read" on storage.objects for select to anon, authenticated
  using (bucket_id = 'posts');
drop policy if exists "posts_files_admin_insert" on storage.objects;
create policy "posts_files_admin_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'posts' and (public.has_perm('notice') or public.has_perm('report') or public.has_perm('statement')));
drop policy if exists "posts_files_admin_update" on storage.objects;
create policy "posts_files_admin_update" on storage.objects for update to authenticated
  using (bucket_id = 'posts' and (public.has_perm('notice') or public.has_perm('report') or public.has_perm('statement')));
drop policy if exists "posts_files_admin_delete" on storage.objects;
create policy "posts_files_admin_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'posts' and (public.is_admin()
         or (owner = auth.uid() and (public.has_perm('notice') or public.has_perm('report') or public.has_perm('statement')))));

-- 재정공개 첨부파일 (비공개 저장소: 볼 수 있는 사람에게만 임시 링크 발급)
insert into storage.buckets (id, name, public) values ('finance', 'finance', false)
  on conflict (id) do update set public = false;
drop policy if exists "finance_files_read" on storage.objects;
create policy "finance_files_read" on storage.objects for select to authenticated
  using (bucket_id = 'finance' and public.can_finance());
drop policy if exists "finance_files_insert" on storage.objects;
create policy "finance_files_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'finance' and public.has_perm('finance'));
drop policy if exists "finance_files_update" on storage.objects;
create policy "finance_files_update" on storage.objects for update to authenticated
  using (bucket_id = 'finance' and public.has_perm('finance'));
drop policy if exists "finance_files_delete" on storage.objects;
create policy "finance_files_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'finance' and (public.is_admin() or (owner = auth.uid() and public.has_perm('finance'))));

-- ---------------------------------------------------------------------
-- 4) 회원 게시판: free = 자유게시판(누구나 읽기, 회원 쓰기)
--                 core = 책임회원 게시판(책임회원 이상만 읽기·쓰기)
--                 director = 이사회 게시판(이사·대표이사·이사회 의장·관리자만 읽기·쓰기)
--    도배 방지: 글은 30초에 1개·1시간에 10개, 댓글은 10초에 1개·1시간에 30개까지 (관리자 제외)
-- ---------------------------------------------------------------------
create table if not exists public.board_posts (
  id bigint generated always as identity primary key,
  board text not null check (board in ('free','core')),
  title text not null check (char_length(title) between 1 and 200),
  body text not null check (char_length(body) between 1 and 10000),
  author_id uuid references public.profiles(id) on delete set null,
  author_name text,
  author_role text,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);
alter table public.board_posts add column if not exists images text[] not null default '{}';
alter table public.board_posts drop constraint if exists board_posts_images_check;
alter table public.board_posts add constraint board_posts_images_check check (cardinality(images) <= 5);
alter table public.board_posts add column if not exists author_username text;
alter table public.board_posts drop constraint if exists board_posts_board_check;
alter table public.board_posts add constraint board_posts_board_check check (board in ('free','core','director'));
-- 이사회 게시판 글 분류 (안건·회의록·의결·자료)
alter table public.board_posts add column if not exists category text;
alter table public.board_posts drop constraint if exists board_posts_category_check;
alter table public.board_posts add constraint board_posts_category_check
  check (category is null or (board = 'director' and category in ('안건','회의록','의결','자료')));
alter table public.board_posts enable row level security;

-- 게시판별로 볼 수 있는지 / 관리(남의 글 삭제)할 수 있는지
create or replace function public.board_visible(b text) returns boolean
language sql stable security definer set search_path = public as $$
  select case b when 'free' then true when 'core' then public.can_core_board()
                when 'director' then public.can_director_board() else false end;
$$;
create or replace function public.board_mod(b text) returns boolean
language sql stable security definer set search_path = public as $$
  select case b when 'free' then public.has_perm('board_free') when 'core' then public.has_perm('board_core')
                when 'director' then public.is_admin() else false end;
$$;
create or replace function public.board_label(b text) returns text
language sql immutable as $$
  select case b when 'free' then '자유게시판' when 'core' then '책임회원 게시판' when 'director' then '이사회 게시판' else b end;
$$;

-- 작성자 정보는 서버가 직접 채움 (다른 사람 이름으로 쓰기 불가)
create or replace function public.board_posts_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
declare pr public.profiles;
begin
  if tg_op = 'INSERT' then
    select * into pr from public.profiles where id = auth.uid();
    if not coalesce(pr.is_admin, false) then
      if exists (select 1 from public.board_posts where author_id = auth.uid() and created_at > now() - interval '30 seconds') then
        raise exception 'too_fast';
      end if;
      if (select count(*) from public.board_posts where author_id = auth.uid() and created_at > now() - interval '1 hour') >= 10 then
        raise exception 'too_many';
      end if;
    end if;
    new.author_id := auth.uid();
    -- 자유게시판은 이름을 저장·공개하지 않고 아이디만 남김
    new.author_name := case when new.board = 'free' then null else coalesce(nullif(pr.full_name, ''), pr.username) end;
    new.author_username := pr.username;
    new.author_role := public.member_label(auth.uid());
    new.created_at := now(); new.updated_at := null;
  else
    if current_setting('saebit.anonymize', true) = 'on' then return new; end if;
    new.board := old.board; new.author_id := old.author_id; new.author_name := old.author_name;
    new.author_username := old.author_username;
    new.author_role := old.author_role; new.created_at := old.created_at; new.updated_at := now();
  end if;
  if new.board <> 'director' then new.category := null; end if;
  -- 사진은 해당 게시판 폴더에 올린 것만 연결 가능
  if exists (select 1 from unnest(new.images) x where x not like new.board || '/%') then
    raise exception 'invalid_image_path';
  end if;
  return new;
end; $$;
drop trigger if exists board_posts_stamp on public.board_posts;
create trigger board_posts_stamp before insert or update on public.board_posts
  for each row execute function public.board_posts_stamp();

drop policy if exists "board_read" on public.board_posts;
create policy "board_read" on public.board_posts for select
  using (public.board_visible(board));
drop policy if exists "board_insert" on public.board_posts;
create policy "board_insert" on public.board_posts for insert to authenticated
  with check (public.board_visible(board));
drop policy if exists "board_update" on public.board_posts;
create policy "board_update" on public.board_posts for update to authenticated
  using (author_id = auth.uid()) with check (author_id = auth.uid());
drop policy if exists "board_delete" on public.board_posts;
create policy "board_delete" on public.board_posts for delete to authenticated
  using (author_id = auth.uid() or public.board_mod(board));

-- 게시판 사진 저장소 (비공개: 자유게시판 사진은 누구나, 다른 게시판 사진은 볼 수 있는 사람만 임시 링크)
insert into storage.buckets (id, name, public) values ('board-images', 'board-images', false)
  on conflict (id) do update set public = false;
drop policy if exists "board_images_read" on storage.objects;
create policy "board_images_read" on storage.objects for select to anon, authenticated
  using (bucket_id = 'board-images' and (storage.foldername(name))[1] in ('free','core','director')
         and public.board_visible((storage.foldername(name))[1]));
drop policy if exists "board_images_insert" on storage.objects;
create policy "board_images_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'board-images' and (storage.foldername(name))[2] = auth.uid()::text
         and (storage.foldername(name))[1] in ('free','core','director') and public.board_visible((storage.foldername(name))[1]));
drop policy if exists "board_images_delete" on storage.objects;
create policy "board_images_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'board-images' and ((storage.foldername(name))[2] = auth.uid()::text
         or ((storage.foldername(name))[1] in ('free','core','director') and public.board_mod((storage.foldername(name))[1]))));

-- 댓글 (글을 볼 수 있는 사람만 보고 쓸 수 있음)
create table if not exists public.board_comments (
  id bigint generated always as identity primary key,
  post_id bigint not null references public.board_posts(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 1000),
  author_id uuid references public.profiles(id) on delete set null,
  author_name text,
  author_role text,
  created_at timestamptz not null default now()
);
alter table public.board_comments add column if not exists author_username text;
create index if not exists board_comments_post_idx on public.board_comments(post_id);
alter table public.board_comments enable row level security;

create or replace function public.board_comments_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
declare pr public.profiles; b text;
begin
  select * into pr from public.profiles where id = auth.uid();
  if not coalesce(pr.is_admin, false) then
    if exists (select 1 from public.board_comments where author_id = auth.uid() and created_at > now() - interval '10 seconds') then
      raise exception 'too_fast';
    end if;
    if (select count(*) from public.board_comments where author_id = auth.uid() and created_at > now() - interval '1 hour') >= 30 then
      raise exception 'too_many';
    end if;
  end if;
  select board into b from public.board_posts where id = new.post_id;
  new.author_id := auth.uid();
  new.author_name := case when b = 'free' then null else coalesce(nullif(pr.full_name, ''), pr.username) end;
  new.author_username := pr.username;
  new.author_role := public.member_label(auth.uid());
  new.created_at := now();
  return new;
end; $$;
drop trigger if exists board_comments_stamp on public.board_comments;
create trigger board_comments_stamp before insert on public.board_comments
  for each row execute function public.board_comments_stamp();

-- 댓글이 달리면 글쓴이에게 알림
create or replace function public.board_comments_after() returns trigger
language plpgsql security definer set search_path = public as $$
declare a uuid; t text;
begin
  select author_id, title into a, t from public.board_posts where id = new.post_id;
  if a is not null and a is distinct from new.author_id then
    perform public.notify(a, 'comment', '내 글에 댓글이 달렸습니다: ' || left(t, 40), 'bp-' || new.post_id);
  end if;
  return new;
end; $$;
drop trigger if exists board_comments_after on public.board_comments;
create trigger board_comments_after after insert on public.board_comments
  for each row execute function public.board_comments_after();

-- 남의 글·댓글을 관리 권한으로 지우면 관리 기록에 남김
create or replace function public.board_posts_after_delete() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if old.author_id is distinct from auth.uid() then
    perform public.log_action('게시판 글 삭제', public.board_label(old.board) || ' · ' || old.title,
      '작성자 ' || coalesce(old.author_username, old.author_name, '-'));
  end if;
  return old;
end; $$;
drop trigger if exists board_posts_after_delete on public.board_posts;
create trigger board_posts_after_delete after delete on public.board_posts
  for each row execute function public.board_posts_after_delete();
create or replace function public.board_comments_after_delete() returns trigger
language plpgsql security definer set search_path = public as $$
declare b public.board_posts;
begin
  select * into b from public.board_posts where id = old.post_id;
  if b.id is null then return old; end if;   -- 글과 함께 지워진 댓글은 따로 남기지 않음
  if old.author_id is distinct from auth.uid() then
    perform public.log_action('댓글 삭제', public.board_label(b.board) || ' · ' || b.title,
      '작성자 ' || coalesce(old.author_username, old.author_name, '-') || ' · ' || left(old.body, 80));
  end if;
  return old;
end; $$;
drop trigger if exists board_comments_after_delete on public.board_comments;
create trigger board_comments_after_delete after delete on public.board_comments
  for each row execute function public.board_comments_after_delete();

create or replace function public.can_see_post(pid bigint) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.board_posts b where b.id = pid and public.board_visible(b.board));
$$;
create or replace function public.can_mod_post(pid bigint) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.board_posts b where b.id = pid and public.board_mod(b.board));
$$;
-- 이미 쓴 글·댓글에도 작성자 아이디를 채워 넣음 (자유게시판에 표시)
alter table public.board_posts disable trigger board_posts_stamp;
update public.board_posts b set author_username = pr.username from public.profiles pr where pr.id = b.author_id and b.author_username is null;
update public.board_posts set author_name = null where board = 'free' and author_name is not null;
alter table public.board_posts enable trigger board_posts_stamp;
update public.board_comments c set author_username = pr.username from public.profiles pr where pr.id = c.author_id and c.author_username is null;
update public.board_comments c set author_name = null from public.board_posts b where b.id = c.post_id and b.board = 'free' and c.author_name is not null;

-- 자유게시판에서 아이디를 누르면 보이는 회원정보 (관리자, 자유게시판 관리 권한자만)
create or replace function public.member_info(u text) returns json
language plpgsql stable security definer set search_path = public as $$
declare p public.profiles;
begin
  if not public.has_perm('board_free') then raise exception 'permission denied'; end if;
  select * into p from public.profiles where username = lower(trim(u));
  if p.id is null then return null; end if;
  return json_build_object(
    'full_name', p.full_name, 'username', p.username, 'email', p.email, 'roles', p.roles,
    'supporter', public.is_supporter(p.id), 'created_at', p.created_at,
    'posts', (select count(*) from public.board_posts where author_id = p.id and board = 'free'),
    'comments', (select count(*) from public.board_comments c join public.board_posts b on b.id = c.post_id
                  where c.author_id = p.id and b.board = 'free'));
end; $$;
revoke all on function public.member_info(text) from public;
grant execute on function public.member_info(text) to authenticated;

drop policy if exists "comments_read" on public.board_comments;
create policy "comments_read" on public.board_comments for select using (public.can_see_post(post_id));
drop policy if exists "comments_insert" on public.board_comments;
create policy "comments_insert" on public.board_comments for insert to authenticated
  with check (auth.uid() is not null and public.can_see_post(post_id));
drop policy if exists "comments_delete" on public.board_comments;
create policy "comments_delete" on public.board_comments for delete to authenticated
  using (author_id = auth.uid() or public.can_mod_post(post_id));

-- ---------------------------------------------------------------------
-- 5) 대표이사 인사말 (누구나 읽기, 대표이사 등급만 수정)
-- ---------------------------------------------------------------------
create table if not exists public.site_content (
  key text primary key,
  body text not null,
  signer text,
  updated_at timestamptz,
  updated_by uuid references public.profiles(id) on delete set null
);
alter table public.site_content enable row level security;
insert into public.site_content (key, body, signer) values ('ceo_greeting',
'새빛 홈페이지를 찾아 주신 여러분, 반갑습니다. 새빛 대표이사 조성만입니다.

새빛은 ‘새로운 빛’이라는 이름처럼, 우리 사회의 어두운 곳에 작은 빛을 더하고 싶은 마음에서 시작했습니다. 사회의 문제는 누군가 대신 풀어 주기를 기다릴 때보다, 그 문제를 겪는 사람들이 함께 목소리를 낼 때 더 빨리 해결된다고 믿습니다.

그래서 새빛은 나이와 배경을 가리지 않고 모두의 목소리를 듣고, 그 목소리를 근거 있는 연구와 구체적인 정책 제안으로 바꾸는 일을 합니다. 서로 다른 생각이 모여 하나의 방향을 찾는 ‘화합’, 그 과정에서 우리 모두가 함께 자라는 ‘성장’이 새빛이 가장 소중히 여기는 가치입니다.

새빛의 걸음은 이제 시작입니다. 회원 한 분 한 분의 참여와 후원이 새빛을 움직이는 가장 큰 힘입니다. 더 나은 내일을 향한 길에 여러분과 함께하겠습니다.

감사합니다.', '새빛 대표이사 조성만')
on conflict (key) do nothing;

create or replace function public.site_content_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.key := old.key; new.updated_at := now(); new.updated_by := auth.uid();
  return new;
end; $$;
drop trigger if exists site_content_stamp on public.site_content;
create trigger site_content_stamp before update on public.site_content
  for each row execute function public.site_content_stamp();

drop policy if exists "content_read" on public.site_content;
create policy "content_read" on public.site_content for select using (true);
drop policy if exists "content_ceo_update" on public.site_content;
create policy "content_ceo_update" on public.site_content for update to authenticated
  using (key = 'ceo_greeting' and public.is_ceo()) with check (public.is_ceo());

-- ---------------------------------------------------------------------
-- 6) 회원 탈퇴: 본인이 신청 → 관리자 또는 '회원 탈퇴 승인' 권한자가 승인(또는 반려)
--    승인 전까지는 탈퇴 대기. 승인하면 글·댓글 작성자는 '탈퇴한 회원'으로 바꾸고,
--    후원 기록은 금액·날짜만 남긴 뒤 계정을 삭제
-- ---------------------------------------------------------------------
create or replace function public.request_withdrawal(reason text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'permission denied'; end if;
  if exists (select 1 from public.profiles where id = auth.uid() and withdraw_requested_at is null) then
    perform public.notify_perm('withdraw', 'withdraw_new',
      (select username from public.profiles where id = auth.uid()) || ' 회원이 탈퇴를 신청했습니다', 'admin');
  end if;
  update public.profiles set withdraw_requested_at = now(), withdraw_reason = left(nullif(trim(reason), ''), 300)
   where id = auth.uid();
end; $$;
create or replace function public.cancel_withdrawal() returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set withdraw_requested_at = null, withdraw_reason = null where id = auth.uid();
end; $$;
create or replace function public.reject_withdrawal(target uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.has_perm('withdraw') then raise exception 'permission denied'; end if;
  if exists (select 1 from public.profiles where id = target and withdraw_requested_at is not null) then
    perform public.log_action('탈퇴 반려', (select username from public.profiles where id = target), null);
    perform public.notify(target, 'withdraw', '탈퇴 신청이 반려되었습니다. 궁금한 점은 1:1 문의로 연락해 주세요', 'mypage');
  end if;
  update public.profiles set withdraw_requested_at = null, withdraw_reason = null where id = target;
end; $$;
create or replace function public.approve_withdrawal(target uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.has_perm('withdraw') then raise exception 'permission denied'; end if;
  if target = auth.uid() then raise exception 'cannot_approve_self'; end if;
  if not exists (select 1 from public.profiles where id = target and withdraw_requested_at is not null) then
    raise exception 'not_requested';
  end if;
  perform public.log_action('탈퇴 승인', (select username from public.profiles where id = target), null);
  perform set_config('saebit.anonymize', 'on', true);
  update public.board_posts set author_name = '탈퇴한 회원', author_username = null, author_role = null where author_id = target;
  update public.board_comments set author_name = '탈퇴한 회원', author_username = null, author_role = null where author_id = target;
  update public.posts set author_name = '탈퇴한 회원', author_role = null where author_id = target;
  update public.donations set photo_path = '(삭제됨)', memo = null, donor_ref = gen_random_uuid() where user_id = target;
  update public.donations d set donor_ref = x.ref from (select donor_ref ref from public.donations where user_id = target limit 1) x
   where d.user_id = target;   -- 같은 사람의 후원은 같은 익명 값으로 묶음
  delete from auth.users where id = target;   -- 회원 정보(profiles)도 함께 삭제됨
  perform set_config('saebit.anonymize', 'off', true);
end; $$;
revoke all on function public.request_withdrawal(text) from public;
revoke all on function public.cancel_withdrawal() from public;
revoke all on function public.reject_withdrawal(uuid) from public;
revoke all on function public.approve_withdrawal(uuid) from public;
grant execute on function public.request_withdrawal(text) to authenticated;
grant execute on function public.cancel_withdrawal() to authenticated;
grant execute on function public.reject_withdrawal(uuid) to authenticated;
grant execute on function public.approve_withdrawal(uuid) to authenticated;

-- ---------------------------------------------------------------------
-- 7) 게시판 신고: 볼 수 있는 글·댓글을 회원이 신고 → 그 게시판 관리 권한자가 처리
--    (자유게시판: 자유게시판 관리 / 책임회원 게시판: 책임회원 게시판 관리 / 이사회 게시판: 관리자)
-- ---------------------------------------------------------------------
create table if not exists public.board_reports (
  id bigint generated always as identity primary key,
  post_id bigint not null,
  comment_id bigint,
  board text not null,
  reason text not null check (reason in ('욕설·비방','광고·도배','개인정보 노출','음란·불법','기타')),
  detail text check (char_length(detail) <= 300),
  snapshot text,
  target_author text,
  reporter_id uuid default auth.uid() references public.profiles(id) on delete set null,
  status text not null default 'open' check (status in ('open','removed','dismissed')),
  handled_by text,
  handled_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index if not exists board_reports_once on public.board_reports (reporter_id, post_id, coalesce(comment_id, 0));
alter table public.board_reports enable row level security;

create or replace function public.board_reports_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
declare bp public.board_posts; cm public.board_comments;
begin
  if auth.uid() is null then raise exception 'permission denied'; end if;
  select * into bp from public.board_posts where id = new.post_id;
  if bp.id is null or not public.board_visible(bp.board) then raise exception 'not_found'; end if;
  if (select count(*) from public.board_reports where reporter_id = auth.uid() and created_at > now() - interval '1 day') >= 20 then
    raise exception 'too_many';
  end if;
  new.reporter_id := auth.uid(); new.board := bp.board; new.status := 'open';
  new.handled_by := null; new.handled_at := null; new.created_at := now();
  if new.comment_id is not null then
    select * into cm from public.board_comments where id = new.comment_id and post_id = bp.id;
    if cm.id is null then raise exception 'not_found'; end if;
    if cm.author_id = auth.uid() then raise exception 'own_content'; end if;
    new.snapshot := left(cm.body, 300);
    new.target_author := coalesce(cm.author_username, cm.author_name);
  else
    if bp.author_id = auth.uid() then raise exception 'own_content'; end if;
    new.snapshot := left(bp.title || E'\n' || bp.body, 300);
    new.target_author := coalesce(bp.author_username, bp.author_name);
  end if;
  return new;
end; $$;
drop trigger if exists board_reports_stamp on public.board_reports;
create trigger board_reports_stamp before insert on public.board_reports
  for each row execute function public.board_reports_stamp();

create or replace function public.board_reports_after() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.notify_perm(case new.board when 'free' then 'board_free' when 'core' then 'board_core' else '_admin_only' end,
    'report', '신고 접수: ' || public.board_label(new.board) || ' · ' || new.reason, 'admin');
  return new;
end; $$;
drop trigger if exists board_reports_after on public.board_reports;
create trigger board_reports_after after insert on public.board_reports
  for each row execute function public.board_reports_after();

drop policy if exists "reports_insert" on public.board_reports;
create policy "reports_insert" on public.board_reports for insert to authenticated with check (true);
drop policy if exists "reports_read" on public.board_reports;
create policy "reports_read" on public.board_reports for select to authenticated
  using (reporter_id = auth.uid() or public.board_mod(board));

-- 신고 처리: removed = 글·댓글 삭제함, dismissed = 문제 없음, open = 다시 열기
create or replace function public.resolve_report(rid bigint, st text) returns void
language plpgsql security definer set search_path = public as $$
declare r public.board_reports; who text;
begin
  select * into r from public.board_reports where id = rid;
  if r.id is null then raise exception 'not_found'; end if;
  if not public.board_mod(r.board) then raise exception 'permission denied'; end if;
  if st not in ('open','removed','dismissed') then raise exception 'invalid_status'; end if;
  select coalesce(nullif(full_name, ''), username) || ' (' || username || ')' into who from public.profiles where id = auth.uid();
  if st = 'removed' then
    -- 신고한 사람들에게 처리 결과 알림
    insert into public.notifications (user_id, kind, title, link)
    select distinct reporter_id, 'report_done',
           '신고하신 ' || case when r.comment_id is null then '글' else '댓글' end || '을 삭제했습니다. 신고해 주셔서 감사합니다', r.board
      from public.board_reports
     where status = 'open' and post_id = r.post_id and (r.comment_id is null or comment_id = r.comment_id)
       and reporter_id is not null;
    -- 같은 글(댓글)에 들어온 다른 신고도 함께 처리
    update public.board_reports set status = 'removed', handled_by = who, handled_at = now()
     where status = 'open' and post_id = r.post_id
       and (r.comment_id is null or comment_id = r.comment_id);
  elsif st = 'dismissed' and r.status = 'open' then
    perform public.notify(r.reporter_id, 'report_done',
      '신고하신 ' || case when r.comment_id is null then '글' else '댓글' end || '을 검토했지만 운영 원칙에 어긋나지 않아 그대로 둡니다', r.board);
  end if;
  update public.board_reports set status = st, handled_by = case when st = 'open' then null else who end,
         handled_at = case when st = 'open' then null else now() end
   where id = rid;
  perform public.log_action('신고 처리', public.board_label(r.board) || ' · ' || coalesce(r.target_author, '-'),
    case st when 'removed' then '삭제 처리' when 'dismissed' then '문제 없음' else '다시 열기' end || ' · ' || r.reason);
end; $$;
revoke all on function public.resolve_report(bigint, text) from public, anon;
grant execute on function public.resolve_report(bigint, text) to authenticated;

-- ---------------------------------------------------------------------
-- 8) 행사·교육: 누구나 보기, '행사·교육 관리' 권한자가 등록, 수정은 자기 행사만(관리자는 전부), 삭제는 관리자만
--    회원이 신청(정원·마감 확인), 본인과 담당자만 신청 내역을 봄
-- ---------------------------------------------------------------------
create table if not exists public.events (
  id bigint generated always as identity primary key,
  title text not null check (char_length(title) between 1 and 200),
  body text check (char_length(body) <= 5000),
  place text check (char_length(place) <= 100),
  starts_at timestamptz not null,
  ends_at timestamptz,
  apply_until timestamptz,
  capacity integer check (capacity is null or capacity > 0),
  closed boolean not null default false,
  author_id uuid references public.profiles(id) on delete set null,
  author_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);
alter table public.events enable row level security;
create or replace function public.events_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.author_id := auth.uid();
    new.author_name := (select coalesce(nullif(full_name, ''), username) from public.profiles where id = auth.uid());
    new.created_at := now(); new.updated_at := null;
  else
    new.author_id := old.author_id; new.author_name := old.author_name;
    new.created_at := old.created_at; new.updated_at := now();
  end if;
  return new;
end; $$;
drop trigger if exists events_stamp on public.events;
create trigger events_stamp before insert or update on public.events
  for each row execute function public.events_stamp();
create or replace function public.events_after_delete() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.log_action('행사 삭제', old.title, to_char(old.starts_at at time zone 'Asia/Seoul', 'YYYY.MM.DD HH24:MI'));
  update public.delete_requests set status = 'approved', handled_at = now(),
         handled_by = coalesce((select coalesce(nullif(full_name, ''), username) || ' (' || username || ')' from public.profiles where id = auth.uid()), '관리자')
   where target_type = 'event' and target_id = old.id and status = 'pending';
  return old;
end; $$;
drop trigger if exists events_after_delete on public.events;
create trigger events_after_delete after delete on public.events
  for each row execute function public.events_after_delete();

-- 새 행사가 올라오면 모든 회원에게 알림 (등록한 사람 제외)
create or replace function public.events_after_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.notifications (user_id, kind, title, link)
  select pr.id, 'new_event', '새 행사·교육: ' || left(new.title, 60), 'ev-' || new.id
    from public.profiles pr where pr.id is distinct from new.author_id;
  return new;
end; $$;
drop trigger if exists events_after_insert on public.events;
create trigger events_after_insert after insert on public.events
  for each row execute function public.events_after_insert();

drop policy if exists "events_read" on public.events;
create policy "events_read" on public.events for select using (true);
drop policy if exists "events_insert" on public.events;
create policy "events_insert" on public.events for insert to authenticated with check (public.has_perm('event'));
drop policy if exists "events_update" on public.events;
create policy "events_update" on public.events for update to authenticated
  using (public.has_perm('event') and author_id = auth.uid()) with check (public.has_perm('event') and author_id = auth.uid());
drop policy if exists "events_delete" on public.events;
create policy "events_delete" on public.events for delete to authenticated using (public.is_admin());

create table if not exists public.event_applications (
  id bigint generated always as identity primary key,
  event_id bigint not null references public.events(id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  full_name text,
  username text,
  email text,
  note text check (char_length(note) <= 300),
  created_at timestamptz not null default now(),
  unique (event_id, user_id)
);
alter table public.event_applications enable row level security;
create or replace function public.event_apps_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
declare ev public.events; pr public.profiles;
begin
  if auth.uid() is null then raise exception 'permission denied'; end if;
  select * into ev from public.events where id = new.event_id for update;   -- 동시에 신청해도 정원을 넘지 않게
  if ev.id is null then raise exception 'not_found'; end if;
  if ev.closed or now() > coalesce(ev.apply_until, ev.starts_at) then raise exception 'event_closed'; end if;
  if ev.capacity is not null and (select count(*) from public.event_applications where event_id = ev.id) >= ev.capacity then
    raise exception 'event_full';
  end if;
  select * into pr from public.profiles where id = auth.uid();
  new.user_id := auth.uid(); new.full_name := pr.full_name; new.username := pr.username; new.email := pr.email;
  new.created_at := now();
  return new;
end; $$;
drop trigger if exists event_apps_stamp on public.event_applications;
create trigger event_apps_stamp before insert on public.event_applications
  for each row execute function public.event_apps_stamp();

drop policy if exists "apps_read" on public.event_applications;
create or replace function public.can_manage_event(eid bigint) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin() or (public.has_perm('event') and exists (select 1 from public.events where id = eid and author_id = auth.uid()));
$$;
create policy "apps_read" on public.event_applications for select to authenticated
  using (user_id = auth.uid() or public.can_manage_event(event_id));
drop policy if exists "apps_insert" on public.event_applications;
create policy "apps_insert" on public.event_applications for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "apps_delete" on public.event_applications;
create policy "apps_delete" on public.event_applications for delete to authenticated
  using (user_id = auth.uid() or public.can_manage_event(event_id));

-- 신청·취소가 생기면 행사를 올린 사람과 관리자에게 알림
create or replace function public.event_apps_notify() returns trigger
language plpgsql security definer set search_path = public as $$
declare ev public.events; r public.event_applications; msg text;
begin
  if tg_op = 'INSERT' then r := new; else r := old; end if;
  select * into ev from public.events where id = r.event_id;
  if ev.id is null then return null; end if;   -- 행사와 함께 지워진 신청은 알리지 않음
  msg := case when tg_op = 'INSERT' then '행사 신청: ' else '행사 신청 취소: ' end || left(ev.title, 40) || ' · ' || coalesce(r.full_name, r.username, '회원');
  insert into public.notifications (user_id, kind, title, link)
  select pr.id, 'event_app', msg, 'ev-' || ev.id from public.profiles pr
   where pr.is_admin or pr.id = ev.author_id;
  return null;
end; $$;
drop trigger if exists event_apps_notify on public.event_applications;
create trigger event_apps_notify after insert or delete on public.event_applications
  for each row execute function public.event_apps_notify();

-- 행사별 신청 인원 (누구나 볼 수 있는 숫자만)
create or replace function public.event_counts() returns json
language sql stable security definer set search_path = public as $$
  select coalesce(json_object_agg(event_id, n), '{}'::json)
    from (select event_id, count(*) n from public.event_applications group by 1) x;
$$;
grant execute on function public.event_counts() to anon, authenticated;

-- ---------------------------------------------------------------------
-- 9) 방문 통계: 날짜별 방문 수만 셈 (개인을 알아볼 수 있는 정보는 저장하지 않음)
-- ---------------------------------------------------------------------
create table if not exists public.site_visits (
  day date primary key,
  views integer not null default 0,
  visitors integer not null default 0
);
alter table public.site_visits enable row level security;
drop policy if exists "visits_admin_read" on public.site_visits;
create policy "visits_admin_read" on public.site_visits for select to authenticated using (public.is_admin());
create or replace function public.log_visit(first_today boolean) returns void
language sql security definer set search_path = public as $$
  insert into public.site_visits (day, views, visitors)
  values ((now() at time zone 'Asia/Seoul')::date, 1, case when first_today then 1 else 0 end)
  on conflict (day) do update set views = public.site_visits.views + 1,
     visitors = public.site_visits.visitors + case when first_today then 1 else 0 end;
$$;
grant execute on function public.log_visit(boolean) to anon, authenticated;

-- ---------------------------------------------------------------------
-- 10) 소식지 구독: 누구나 이메일로 구독·취소, '소식지 구독자 관리' 권한자가 명단 관리
-- ---------------------------------------------------------------------
create table if not exists public.newsletter_subscribers (
  id bigint generated always as identity primary key,
  email text not null unique check (char_length(email) <= 254 and email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]{2,}$'),
  consent_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unsubscribed_at timestamptz
);
alter table public.newsletter_subscribers enable row level security;
drop policy if exists "subs_read" on public.newsletter_subscribers;
create policy "subs_read" on public.newsletter_subscribers for select to authenticated using (public.has_perm('newsletter'));
drop policy if exists "subs_delete" on public.newsletter_subscribers;
create policy "subs_delete" on public.newsletter_subscribers for delete to authenticated using (public.has_perm('newsletter'));
create or replace function public.subscribe_newsletter(e text) returns void
language plpgsql security definer set search_path = public as $$
begin
  e := lower(trim(e));
  if e is null or e !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]{2,}$' or char_length(e) > 254 then
    raise exception 'invalid_email';
  end if;
  if not exists (select 1 from public.newsletter_subscribers where email = e and unsubscribed_at is null) then
    perform public.notify_perm('newsletter', 'newsletter', '소식지 새 구독: ' || e, 'admin');
  end if;
  insert into public.newsletter_subscribers (email) values (e)
  on conflict (email) do update set unsubscribed_at = null, consent_at = now();
end; $$;
drop function if exists public.unsubscribe_newsletter(text);
create or replace function public.unsubscribe_newsletter(e text) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.newsletter_subscribers set unsubscribed_at = now()
   where email = lower(trim(e)) and unsubscribed_at is null;
  if found then perform public.notify_perm('newsletter', 'newsletter', '소식지 구독 취소: ' || lower(trim(e)), 'admin'); end if;
end; $$;
grant execute on function public.subscribe_newsletter(text) to anon, authenticated;
grant execute on function public.unsubscribe_newsletter(text) to anon, authenticated;

-- ---------------------------------------------------------------------
-- 11) 이체 확인 사진 보관 기간(처리 후 1년) 정리 · 백업 기록
-- ---------------------------------------------------------------------
create or replace function public.purge_proofs(ids bigint[]) returns integer
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if not public.has_perm('donation') then raise exception 'permission denied'; end if;
  update public.donations set photo_path = '(삭제됨)'
   where id = any(ids) and status <> 'pending' and reviewed_at < now() - interval '1 year' and photo_path <> '(삭제됨)';
  get diagnostics n = row_count;
  if n > 0 then perform public.log_action('증빙 정리', '이체 확인 사진', n || '건 삭제 (처리 후 1년 지남)'); end if;
  return n;
end; $$;
revoke all on function public.purge_proofs(bigint[]) from public, anon;
grant execute on function public.purge_proofs(bigint[]) to authenticated;

create or replace function public.log_export() returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'permission denied'; end if;
  perform public.log_action('데이터 내려받기', '전체 백업', null);
end; $$;
revoke all on function public.log_export() from public, anon;
grant execute on function public.log_export() to authenticated;

-- ---------------------------------------------------------------------
-- 12) 삭제 요청: 권한자는 자기가 쓴 글·행사만 삭제를 '요청'하고, 관리자가 승인하면 삭제
-- ---------------------------------------------------------------------
create table if not exists public.delete_requests (
  id bigint generated always as identity primary key,
  target_type text not null check (target_type in ('post','event')),
  target_id bigint not null,
  target_label text,
  reason text check (char_length(reason) <= 300),
  requested_by uuid default auth.uid() references public.profiles(id) on delete set null,
  requester_name text,
  status text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  handled_by text,
  handled_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index if not exists delete_requests_pending on public.delete_requests (target_type, target_id) where status = 'pending';
alter table public.delete_requests enable row level security;

create or replace function public.delete_requests_stamp() returns trigger
language plpgsql security definer set search_path = public as $$
declare p public.posts; ev public.events;
begin
  if auth.uid() is null then raise exception 'permission denied'; end if;
  if new.target_type = 'post' then
    select * into p from public.posts where id = new.target_id;
    if p.id is null then raise exception 'not_found'; end if;
    if p.author_id is distinct from auth.uid() or not public.has_perm(p.type) then raise exception 'not_own'; end if;
    new.target_label := case p.type when 'notice' then '공지사항' when 'statement' then '성명·논평' when 'report' then '연구보고서' else '재정공개' end || ' · ' || p.title;
  else
    select * into ev from public.events where id = new.target_id;
    if ev.id is null then raise exception 'not_found'; end if;
    if ev.author_id is distinct from auth.uid() or not public.has_perm('event') then raise exception 'not_own'; end if;
    new.target_label := '행사·교육 · ' || ev.title;
  end if;
  new.requested_by := auth.uid();
  new.requester_name := (select coalesce(nullif(full_name, ''), username) || ' (' || username || ')' from public.profiles where id = auth.uid());
  new.status := 'pending'; new.handled_by := null; new.handled_at := null; new.created_at := now();
  return new;
end; $$;
drop trigger if exists delete_requests_stamp on public.delete_requests;
create trigger delete_requests_stamp before insert on public.delete_requests
  for each row execute function public.delete_requests_stamp();
create or replace function public.delete_requests_after() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.notify_perm('_admin_only', 'delreq_' || new.target_type,
    '삭제 요청: ' || new.target_label || ' · ' || coalesce(new.requester_name, '-'), 'admin');
  return new;
end; $$;
drop trigger if exists delete_requests_after on public.delete_requests;
create trigger delete_requests_after after insert on public.delete_requests
  for each row execute function public.delete_requests_after();

drop policy if exists "delreq_insert" on public.delete_requests;
create policy "delreq_insert" on public.delete_requests for insert to authenticated with check (true);
drop policy if exists "delreq_read" on public.delete_requests;
create policy "delreq_read" on public.delete_requests for select to authenticated
  using (requested_by = auth.uid() or public.is_admin());

-- 요청한 사람이 대기 중인 요청을 취소
create or replace function public.cancel_delete_request(rid bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.delete_requests set status = 'cancelled', handled_at = now()
   where id = rid and requested_by = auth.uid() and status = 'pending';
  if not found then raise exception 'already_done'; end if;
end; $$;
-- 관리자가 승인(삭제) 또는 반려
drop function if exists public.decide_delete_request(bigint, boolean);
create or replace function public.decide_delete_request(rid bigint, approve boolean) returns json
language plpgsql security definer set search_path = public as $$
declare r public.delete_requests; who text; f json;
begin
  if not public.is_admin() then raise exception 'permission denied'; end if;
  select * into r from public.delete_requests where id = rid for update;
  if r.id is null then raise exception 'not_found'; end if;
  if r.status <> 'pending' then raise exception 'already_done'; end if;
  select coalesce(nullif(full_name, ''), username) || ' (' || username || ')' into who from public.profiles where id = auth.uid();
  if approve then
    if r.target_type = 'post' then
      select json_build_object('bucket', case when type = 'finance' then 'finance' else 'posts' end, 'path', file_path)
        into f from public.posts where id = r.target_id and file_path is not null;
      delete from public.posts where id = r.target_id;
    else delete from public.events where id = r.target_id; end if;
    update public.delete_requests set status = 'approved', handled_by = who, handled_at = now() where id = rid;
    perform public.log_action('삭제 요청 승인', r.target_label, '요청 ' || coalesce(r.requester_name, '-'));
    perform public.notify(r.requested_by, 'delreq_done', '삭제 요청을 승인해 삭제했습니다: ' || r.target_label, 'mypage');
  else
    update public.delete_requests set status = 'rejected', handled_by = who, handled_at = now() where id = rid;
    perform public.log_action('삭제 요청 반려', r.target_label, '요청 ' || coalesce(r.requester_name, '-'));
    perform public.notify(r.requested_by, 'delreq_done', '삭제 요청이 반려되었습니다: ' || r.target_label, 'mypage');
  end if;
  return f;
end; $$;
revoke all on function public.cancel_delete_request(bigint) from public, anon;
revoke all on function public.decide_delete_request(bigint, boolean) from public, anon;
grant execute on function public.cancel_delete_request(bigint) to authenticated;
grant execute on function public.decide_delete_request(bigint, boolean) to authenticated;

-- =====================================================================
-- 13) 관리자 지정 — 사이트에서 본인 계정으로 회원가입한 뒤,
--    아래 줄의 '내아이디'를 본인 아이디로 바꾸고 이 줄만 다시 실행하세요.
-- =====================================================================
-- update public.profiles set is_admin = true where username = '내아이디';
