import { join } from 'path';
// @ts-ignore
import dirname from 'es-dirname';
import dotenv from 'dotenv';
import _pg from 'pg-promise';

dotenv.config({ path: join(dirname(), '..', '.env') });

export const pg = _pg({});

export const db = pg({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.HOST_PORT!),
    database: process.env.POSTGRES_DB,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
});
