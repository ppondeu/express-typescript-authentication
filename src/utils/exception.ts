class HttpException extends Error {
    constructor(public status: number, public message: string) {
        super(message);

        Object.setPrototypeOf(this, new.target.prototype); // Correctly set prototype
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

class BadRequestException extends HttpException {
    constructor(message: string = 'Bad Request') {
        super(400, message);
    }
}

class UnauthorizedException extends HttpException {
    constructor(message: string = 'Unauthorized') {
        super(401, message);
    }
}

class ForbiddenException extends HttpException {
    constructor(message: string = 'Forbidden') {
        super(403, message);
    }
}

class NotFoundException extends HttpException {
    constructor(message: string = 'Not Found') {
        super(404, message);
    }
}

class ConflictException extends HttpException {
    constructor(message: string = 'Conflict') {
        super(409, message);
    }
}

class UnprocessableEntityException extends HttpException {
    constructor(message: string = 'Unprocessable Entity') {
        super(422, message);
    }
}

class InternalServerErrorException extends HttpException {
    constructor(message: string = 'Internal Server Error') {
        super(500, message);
    }
}

export {
    HttpException,
    BadRequestException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    ConflictException,
    UnprocessableEntityException,
    InternalServerErrorException
}

// try {
//   throw new NotFoundException();
// } catch (err) {
//   if (err instanceof HttpException) {
//     console.log(`error: ${err.status} - ${err.message}`);
//   } else {
//     console.log(`unknow error: ${err}`);
//   }
// }

// const test = async (flag: boolean) => {
//     if (!flag) throw "unknow"
//     return "hello, world";
// }

// const func = async (flag: boolean = false) => {
//     let result: string;
//     try {
//         result = await test(flag);
//         console.log("resolve ", result);
//     } catch (err) {
//         if (err instanceof HttpException) {
//             console.log(`HttpException: ${err.status} - ${err.message}`)
//         } else if (err instanceof Error) {
//             console.log("Error", err.message);
//         } else {
//             console.log("Unknown", err);
//         }
//     } finally {
//         console.log("finally");
//     }
// }

// func();