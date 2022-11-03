create table users (
  id varchar(255) primary key,
  name varchar(255) unique not null,
  password_hash text not null,
  refresh_token_hash text,
  created_at timestamp not null,
  updated_at timestamp not null
);
