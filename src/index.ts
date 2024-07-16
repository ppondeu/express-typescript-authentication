import express from "express";
import { Request, Response, NextFunction } from "express-serve-static-core"
import cookieParser from "cookie-parser";
import cors from "cors";
import userRouter from "./routes/user.route";
import authRouter from "./routes/auth.route";
import { SERVER_PORT } from "./config/config";
import verifyToken from "./middleware/verifyToken";
import { HttpException } from "./utils/exception";
import { ApiResponse } from "./dtos/ApiResponse.dto";

const app = express();

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true
}))
app.use("/api/users", verifyToken, userRouter)
app.use("/api/auth", authRouter)

app.get("/", (_req: Request, res: Response, _next: NextFunction) => {
    res.send("Hello, World!");
});

app.get("/ping", (_req: Request, res: Response, _next: NextFunction) => {
    res.send("pong");
});

// handle 404
app.use((_req: Request, res: Response) => {
    res.status(404).send("404 Not Found");
});

// handle errors
app.use((err: unknown, _req: Request, res: Response<ApiResponse<undefined>>, _next: NextFunction) => {
    if (err instanceof HttpException) {
        return res.status(err.status).json({ success: false, error: err.message });
    } else if (err instanceof Error) {
        return res.status(500).json({ success: false, error: err.message });
    } else {
        return res.status(500).json({ success: false, error: "Internal Server Error" });
    }
});

app.listen(SERVER_PORT, () => console.log(`Server is running on port ${SERVER_PORT}`));
