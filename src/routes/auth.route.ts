import { Router } from "express";
import { fetchMe, login, logout, refreshToken, register } from "../controllers/auth.controller";
import verifyToken from "../middleware/verifyToken";

const router = Router();

router.post("/login", login);
router.post("/register", register);
router.post("/logout", logout);
router.post("/refresh-token", refreshToken);
router.post("/me", verifyToken, fetchMe);

export default router;