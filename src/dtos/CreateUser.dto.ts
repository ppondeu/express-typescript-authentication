import { z } from "zod"

export const CreateUserSchema = z.object({
    name: z.string({ message: "name must be string" }).optional(),
    email: z.string({ message: "email must be a string" }).email("email must be a valid email"),
    password: z.string({ message: "password must be a string" }).min(6, "password must be at least 6 characters"),
})

export type CreateUserDTO = z.infer<typeof CreateUserSchema>