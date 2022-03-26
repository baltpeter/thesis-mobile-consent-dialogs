-- Some parts reused from projprakt.
create type platform_enum as enum ('android', 'ios');

alter type platform_enum owner to ma;

create type verdict_enum as enum ('neither', 'dialog', 'notice', 'maybe_dialog', 'maybe_notice', 'link');

alter type verdict_enum owner to ma;

create type run_type as enum ('initial', 'accepted', 'rejected');

alter type run_type owner to ma;

create table if not exists apps
(
    name text not null,
    version text not null,
    platform platform_enum not null,
    id serial
        constraint apps_pk
            primary key
);

alter table apps owner to ma;

create table if not exists runs
(
    id serial
        constraint run_pk
            primary key,
    start_time timestamp with time zone,
    end_time timestamp with time zone,
    app integer not null
        constraint runs_apps_id_fk
            references apps
                on delete cascade,
    run_type run_type not null
);

alter table runs owner to ma;

create table if not exists requests
(
    id serial
        constraint request_pk
            primary key,
    run integer
        constraint request_run_id_fk
            references runs
                on delete cascade,
    start_time timestamp with time zone not null,
    method varchar(10) not null,
    host text not null,
    path text not null,
    content text,
    content_raw bytea not null,
    port integer,
    scheme text not null,
    authority text,
    http_version text not null
);

alter table requests owner to ma;

create table if not exists headers
(
    id serial
        constraint headers_pk
            primary key,
    request integer
        constraint table_name_requests_id_fk
            references requests
                on delete cascade,
    name text not null,
    values text[]
);

alter table headers owner to ma;

create table if not exists cookies
(
    id serial
        constraint cookies_pk
            primary key,
    request integer
        constraint table_name_requests_id_fk
            references requests
                on delete cascade,
    name text not null,
    values text[]
);

alter table cookies owner to ma;

create table if not exists trailers
(
    id serial
        constraint trailers_pk
            primary key,
    request integer
        constraint table_name_requests_id_fk
            references trailers
                on delete cascade,
    name text not null,
    values text[]
);

alter table trailers owner to ma;

create table if not exists dialogs
(
    id serial
        constraint dialogs_pk
            primary key,
    run integer
        constraint dialogs_runs_id_fk
            references runs
                on delete cascade,
    verdict verdict_enum not null,
    violations jsonb not null,
    prefs jsonb not null,
    screenshot bytea,
    meta jsonb not null
);

alter table dialogs owner to ma;
