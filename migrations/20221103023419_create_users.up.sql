create table users (
  id text primary key,
  name text unique not null,
  password_hash text not null,
  refresh_token_hash text,
  created_at timestamptz not null,
  updated_at timestamptz not null
);
