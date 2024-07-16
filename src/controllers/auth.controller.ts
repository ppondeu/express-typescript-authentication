import { Request, Response, NextFunction } from "express-serve-static-core";
import bcrypt from "bcrypt";
import jwt, { JsonWebTokenError, JwtPayload, TokenExpiredError } from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import pool from "../config/db";
import { handleError } from "../utils/errs";
import { ACCESS_TOKEN_EXPIRES_IN, ACCESS_TOKEN_SECRET, REFRESH_TOKEN_EXPIRES_IN, REFRESH_TOKEN_SECRET, SALT_ROUNDS } from "../config/config";
import { BadRequestException, ForbiddenException, InternalServerErrorException, NotFoundException, UnauthorizedException, UnprocessableEntityException } from "../utils/exception";
import { ApiResponse } from "../dtos/ApiResponse.dto";
import { UserResponse } from "../dtos/UserResponse.dto";
import { LoginPayloadSchema } from "../dtos/LoginPayload.dto";
import { CreateUserSchema } from "../dtos/CreateUser.dto";

const db = pool;

export const login = async (req: Request, res: Response<ApiResponse<{ token: string }>>, next: NextFunction) => {
    const loginPayload = LoginPayloadSchema.safeParse(req.body);
    if (!loginPayload.success) {
        const errorMessage = loginPayload.error.errors.map((err) => `${err.path.join('.')} - ${err.message}`).join('; ');
        return next(new UnprocessableEntityException(errorMessage));
    }

    const { email, password } = loginPayload.data;

    let query: string, values: any[];
    query = `SELECT * FROM users WHERE email = $1`;
    values = [email];
    try {
        const { rows } = await db.query(query, values);
        if (rows.length === 0) return next(new NotFoundException("user not found"));

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return next(new BadRequestException("invalid password"));

        const accessToken = jwt.sign({ sub: user.id }, ACCESS_TOKEN_SECRET!, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
        const refreshToken = jwt.sign({ sub: user.id }, REFRESH_TOKEN_SECRET!, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });

        query = `UPDATE users SET refresh_token = $1 WHERE id = $2`;
        values = [refreshToken, user.id];
        await db.query(query, values);

        res.cookie("accessToken", accessToken, { httpOnly: true, expires: new Date(Date.now() + 60 * 1000) });
        res.cookie("refreshToken", refreshToken, { httpOnly: true, expires: new Date(Date.now() + 60 * 60 * 1000) });
        console.log(`access token expired time in cookie: ${new Date(Date.now() + 60 * 1000)}`);
        res.json({ success: true, data: { token: accessToken } });
    } catch (err) {
        console.log(`error in login`, err);
        handleError(err, "auth controller login");
        next(err);
    }
}

export const register = async (req: Request, res: Response<ApiResponse<{ user: UserResponse, token: string }>>, next: NextFunction) => {
    const registerPayload = CreateUserSchema.safeParse(req.body);
    if (!registerPayload.success) {
        const errorMessage = registerPayload.error.errors.map((err) => `${err.path.join('.')} - ${err.message}`).join('; ');
        return next(new UnprocessableEntityException(errorMessage));
    }

    try {
        const { name, email, password } = registerPayload.data;

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const userId = uuidv4();

        const accessToken = jwt.sign({ sub: userId }, ACCESS_TOKEN_SECRET!, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
        const refreshToken = jwt.sign({ sub: userId }, REFRESH_TOKEN_SECRET!, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });

        const query = `
        INSERT INTO users (id, name, email, password, refresh_token)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *`;

        const values = [userId, name, email, hashedPassword, refreshToken];
        let { rows } = await db.query(query, values);
        if (rows.length === 0) return next(new InternalServerErrorException());
        const user = rows[0];

        res.cookie("accessToken", accessToken, { httpOnly: true, expires: new Date(Date.now() + 60 * 1000) });
        res.cookie("refreshToken", refreshToken, { httpOnly: true, expires: new Date(Date.now() + 60 * 60 * 1000) });
        console.log(`access token expired time in cookie: ${new Date(Date.now() + 60 * 1000)}`);
        res.json({ success: true, data: { user: { id: user.id, name: user.name, email: user.email }, token: accessToken } });
    } catch (err) {
        handleError(err, "create user");
        next(err);
    }
}

export const logout = async (req: Request, res: Response<ApiResponse<undefined>>, next: NextFunction) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return next(new ForbiddenException());

    const query = `UPDATE users SET refresh_token = null WHERE refresh_token = $1`;
    const values = [refreshToken];
    try {
        await db.query(query, values);
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.json({ success: true, message: "logout successfully" });
    } catch (err) {
        handleError(err, "auth controller logout");
        next(err);
    }
}

export const refreshToken = async (req: Request, res: Response<ApiResponse<{ token: string }>>, next: NextFunction) => {
    let query: string, values: any[];
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return next(new ForbiddenException());

    res.clearCookie("accessToken");

    let decoded: JwtPayload;
    try {
        decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET!) as JwtPayload;
        if (!decoded || !decoded.sub) {
            console.log(`refresh token not valid`);
            res.clearCookie("refreshToken");
            return next(new ForbiddenException());
        }
    } catch (err) {
        if (err instanceof JsonWebTokenError || err instanceof TokenExpiredError) {
            console.log("error in refresh token", err);
            res.clearCookie("refreshToken");
            return next(new ForbiddenException());
        }
        handleError(err, "auth controller refresh token");
        return next(err);
    }

    query = `SELECT * FROM users WHERE id = $1`;
    values = [decoded.sub];

    let user: any;
    try {
        const { rows } = await db.query(query, values);
        if (rows.length === 0) {
            (`user not found`);
            res.clearCookie("refreshToken");
            return next(new ForbiddenException());
        }

        if (rows.length === 0) return next(new ForbiddenException());

        user = rows[0];

    } catch (err) {
        res.clearCookie("refreshToken");
        handleError(err, "auth controller refresh token");
        return next(err);
    }

    if (user.refresh_token !== refreshToken) {
        console.log(`try to use old refresh token`, user.refresh_token, refreshToken);
        res.clearCookie("refreshToken");

        query = `UPDATE users SET refresh_token = null WHERE id = $1`;
        values = [user.id];
        try {
            await db.query(query, values);
            console.log(`update refresh token to null`);
        } catch (err) {
            handleError(err, "auth controller refresh token");
            return next(err);
        }

        return next(new ForbiddenException());
    }

    const accessToken = jwt.sign({ sub: user.id }, ACCESS_TOKEN_SECRET!, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
    res.cookie("accessToken", accessToken, { httpOnly: true, expires: new Date(Date.now() + 60 * 1000) });
    console.log(`access token expired time in cookie: ${new Date(Date.now() + 60 * 1000)}`);
    res.json({ success: true, data: { token: accessToken } });
}

export const fetchMe = async (req: Request, res: Response<ApiResponse<{ user: UserResponse, token: string }>>, next: NextFunction) => {
    const userID = req.userID as string;

    const query = `SELECT * FROM users WHERE id = $1`;
    const values = [userID];
    try {
        const { rows } = await db.query(query, values);
        if (rows.length === 0) return next(new ForbiddenException());

        const user: UserResponse = {
            id: rows[0].id,
            name: rows[0].name,
            email: rows[0].email,
        };
        res.json({ success: true, data: { user, token: req.cookies.accessToken } });
    } catch (err) {
        handleError(err, "auth controller fetch me");
        next(err);
    }
}