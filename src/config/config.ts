import dotenv from "dotenv";

dotenv.config()

export const SERVER_PORT = process.env.SERVER_PORT || 3000;

export const DB_PORT = parseInt(process.env.DB_PORT!);
export const DB_HOST = process.env.DB_HOST;
export const DB_USERNAME = process.env.DB_USERNAME;
export const DB_PASSWORD = process.env.DB_PASSWORD;
export const DB_DATABASE = process.env.DB_DATABASE;

export const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS!);

export const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
export const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
export const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN;
export const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN;