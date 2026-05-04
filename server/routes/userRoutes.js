import express from "express";
import {
  registerUser,
  loginUser,
  getMe,
  updateUser,
  deleteUser,
  getAllUsers,
  unlockUser,
  requestUnlock,
  verifyUnlock,
} from "../controllers/userController.js";
import { protect, authorizeRoles } from "../middleware/authMiddleware.js";

const router = express.Router();

router.get("/", protect, authorizeRoles("Admin", "Sub Admin"), getAllUsers);
router.post("/", registerUser);
router.post("/login", loginUser);
router.post("/request-unlock", requestUnlock);
router.post("/verify-unlock", verifyUnlock);
router.get("/me", protect, getMe);
router.put("/:id", protect, updateUser);
router.put("/:id/unlock", protect, authorizeRoles("Admin"), unlockUser);
router.delete("/:id", protect, authorizeRoles("Admin"), deleteUser);

export default router;