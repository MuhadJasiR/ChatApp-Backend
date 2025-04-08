import { Router } from "express";
import { register} from "../controller/authController";

const router= Router();

router.post("/register",register);
// router.post("/login",login);
export default router;
