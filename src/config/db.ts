import { Pool } from 'pg';
import { DB_DATABASE, DB_HOST, DB_PASSWORD, DB_PORT, DB_USERNAME } from './config';

console.log(`database connecting...`)
let pool: Pool;
try {
    pool = new Pool({
        user: DB_USERNAME,
        host: DB_HOST,
        database: DB_DATABASE,
        password: DB_PASSWORD,
        port: DB_PORT,
    });
    console.log(`database connect successfully`)

} catch (err) {
    console.log(`database connect failed: ${err}`)
    process.exit(1)
}

export default pool