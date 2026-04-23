import express from "express";
import {
  registerUser,
  loginUser,
  getMe,
  updateUser,
  deleteUser,
  getAllUsers,
} from "../controllers/userController.js";
import { protect, authorizeRoles } from "../middleware/authMiddleware.js";

const router = express.Router();

router.get("/", protect, authorizeRoles("Admin", "Sub Admin"), getAllUsers);
router.post("/", registerUser);
router.post("/login", loginUser);
router.get("/me", protect, getMe);
router.put("/:id", protect, updateUser);
router.delete("/:id", protect, authorizeRoles("Admin"), deleteUser);

export default router;