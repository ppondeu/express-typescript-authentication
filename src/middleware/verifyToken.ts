import { RequestHandler } from 'express-serve-static-core';
import jwt, { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';
import { ACCESS_TOKEN_SECRET } from '../config/config';
import { UnauthorizedException } from '../utils/exception';

const verifyToken: RequestHandler = (req, _res, next) => {
    const accessToken = req.cookies.accessToken as string;
    if (!accessToken) return next(new UnauthorizedException());
    jwt.verify(accessToken, ACCESS_TOKEN_SECRET!, (err, decoded) => {
        if (err) {
            if (err instanceof TokenExpiredError) {
                return next(new UnauthorizedException());
            } else if (err instanceof JsonWebTokenError) {
                return next(new UnauthorizedException());
            } else {
                return next(err);
            }
        }

        if (!decoded || !decoded.sub) {
            console.log(`access token not valid`);
            return next(new UnauthorizedException());
        }

        req.userID = decoded.sub as string;
    });

    next();
}

export default verifyToken;