export interface LoginPayload {
    email: string;
    password: string;
}

import { z } from "zod";

export const LoginPayloadSchema = z.object({
    email: z.string({ message: "email must be a string" }).email("email must be a valid email"),
    password: z.string({ message: "email must be a string" }).min(8, "password must be at least 8 characters"),
});

export type LoginDTO = z.infer<typeof LoginPayloadSchema>;