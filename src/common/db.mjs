import { join } from 'path';
import dirname from 'es-dirname';
(await import('dotenv')).config({ path: join(dirname(), '..', '.env') });
import _pg from 'pg-promise';

export const pg = _pg({});

export const db = pg({
    host: 'localhost',
    port: parseInt(process.env.HOST_PORT),
    database: process.env.POSTGRES_DB,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
});
