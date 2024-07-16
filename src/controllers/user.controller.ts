import { Request, Response, NextFunction } from 'express-serve-static-core';
import { z } from "zod";
import pool from '../config/db';
import { BadRequestException, NotFoundException } from '../utils/exception';
import { handleError } from '../utils/errs';
import { ApiResponse } from '../dtos/ApiResponse.dto';
import { UserResponse } from '../dtos/UserResponse.dto';

const db = pool;

export const getUsers = async (_req: Request, res: Response<ApiResponse<UserResponse[]>>, next: NextFunction) => {
    const query = "SELECT * FROM users";
    try {
        const { rows } = await db.query(query) as { rows: UserResponse[] };
        const users = rows.map((user) => {
            return {
                id: user.id,
                name: user.name,
                email: user.email,
            };
        });
        res.json({ success: true, data: users });
    } catch (err) {
        handleError(err, "user controller get users");
        next(err);
    }
};

export const getUserByID = async (req: Request, res: Response<ApiResponse<UserResponse>>, next: NextFunction) => {
    const idSchema = z.string().uuid("id must be a valid uuid");
    const userIdPayload = idSchema.safeParse(req.params.id);

    if (!userIdPayload.success) {
        return next(new BadRequestException(userIdPayload.error.errors[0].message));
    }

    const query = `SELECT * FROM users WHERE id = $1`;
    const values = [userIdPayload.data];
    try {
        const { rows } = await db.query(query, values);
        if (rows.length === 0) return next(new NotFoundException("user not found"));
        const userResp: UserResponse = {
            id: rows[0].id,
            name: rows[0].name,
            email: rows[0].email,
        };
        res.json({ success: true, data: userResp });
    } catch (err) {
        handleError(err, "user controller get user by id");
        next(err);
    }
}