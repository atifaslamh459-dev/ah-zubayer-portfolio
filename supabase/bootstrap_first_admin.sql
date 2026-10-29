-- NOT a migration. Run ONCE in the Supabase SQL editor after creating your own user
-- (Authentication -> Users -> Add user). There is no public admin signup route; also
-- turn OFF "Allow new users to sign up" in Auth settings.
insert into public.admin_users (user_id)
select id from auth.users where email = 'YOUR_EMAIL@example.com'
on conflict do nothing;

-- Revoke access later:
-- delete from public.admin_users where user_id = (select id from auth.users where email = 'x@example.com');
