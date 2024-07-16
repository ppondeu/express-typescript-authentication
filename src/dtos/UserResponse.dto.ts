import uuid from "uuid";
export type UserResponse = {
    id: uuid.V4Options;
    name: string;
    email: string;
}