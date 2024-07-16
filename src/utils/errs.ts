import { HttpException } from "./exception"

export const handleError = (err: unknown, msg: string) => {
    if (err instanceof HttpException) {
        console.log(`error on ${msg}: ${err.status} - ${err.message}`);
    } else if (err instanceof Error) {
        console.log(`error on ${msg}: ${err.message}`);
    } else {
        console.log(`error on ${msg}: ${err}`);
    }
}
