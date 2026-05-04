import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import User from "../models/user.js";
import Role from "../models/role.js";
import sendEmail from "../utils/sendEmail.js";
import { getLockoutEmailTemplate } from "../utils/emailTemplates.js";
import { checkUserLock, checkThrottle, handleLoginSuccess, handleLoginFailure } from "../services/authService.js";

// Generate JWT token with role payload
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      role: user.Role?.name || "Public User", // Ensure safe fallback
    },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );
};

// @desc Register new user
export const registerUser = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Please add all fields" });
    }

    // Check if user already exists
    const userExists = await User.findOne({ where: { email } });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Default to 'Public User' role (ID: 1 for example) if not provided
    let publicRole = await Role.findOne({ where: { name: "Public User" } });
    if (!publicRole) {
      publicRole = await Role.create({ name: "Public User" }); // fallback creation
    }

    // Create user natively via Sequelize
    const user = await User.create({
      name,
      email,
      password,
      role_id: publicRole.id, // Assign standard role easily
    });

    // Populate role association for token generation immediately
    user.Role = publicRole;

    if (user) {
      try {
        await sendEmail(
          user.email, 
          "Welcome to My App!", 
          `Hi ${user.name},\n\nWelcome to our platform. We are glad to have you!`
        );
      } catch (err) {
        console.error("Welcome email failed", err);
      }

      res.status(201).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        token: generateToken(user),
      });
    } else {
      res.status(400).json({ message: "Invalid user data" });
    }
  } catch (error) {
    next(error);
  }
};

// @desc Authenticate a user
export const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const ipAddress = req.ip;

    const user = await User.findOne({
      where: { email },
      include: Role,
    });

    // 🔒 1. Lock Check
    const lockError = checkUserLock(user);
    if (lockError) {
      return res.status(lockError.status).json({ 
        message: lockError.message,
        ...(lockError.supportUrl && { supportUrl: lockError.supportUrl }),
        requiresVerification: lockError.message.includes("verify")
      });
    }

    // ⏱️ 2. Throttle Check
    const isThrottled = await checkThrottle(user, ipAddress);
    if (isThrottled) {
      // 🚨 Record the failure even while throttled to progress towards Scenario 2 (Blocking)
      const throttleFailure = await handleLoginFailure(user, ipAddress);
      
      // If the throttled attempt triggers the 10th failure lockout, return the 403 response
      if (throttleFailure.status === 403) {
        return res.status(403).json({ 
          message: throttleFailure.message,
          ...(throttleFailure.supportUrl && { supportUrl: throttleFailure.supportUrl })
        });
      }

      return res.status(429).json({ message: "Too many login attempts. Please try again later" });
    }

    // 🔑 3. Password Check
    if (user && (await user.matchPassword(password))) {
      await handleLoginSuccess(user, ipAddress);

      return res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        token: generateToken(user),
      });
    }

    // 🛡️ 4. Artificial Delay (Security Tip)
    await new Promise(res => setTimeout(res, 300));

    // ❌ 5. Failure Check
    const failureResult = await handleLoginFailure(user, ipAddress);
    return res.status(failureResult.status).json({ 
      message: failureResult.message,
      ...(failureResult.supportUrl && { supportUrl: failureResult.supportUrl }),
      requiresVerification: failureResult.message.includes("verify")
    });

  } catch (error) {
    next(error);
  }
};

// @desc Get user data
export const getMe = async (req, res, next) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    next(error);
  }
};

// @desc Update user profile
export const updateUser = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verification check to assure users ONLY update their own profiles
    if (user.id.toString() !== req.user.id.toString()) {
      return res.status(401).json({ message: "User not authorized" });
    }

    // Effectively map the updates to the object via Sequelize updates
    await user.update(req.body);

    res.status(200).json(user);
  } catch (error) {
    next(error);
  }
};

// @desc Delete user account
export const deleteUser = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.id.toString() !== req.user.id.toString()) {
      return res.status(401).json({ message: "User not authorized" });
    }

    // Using destruction natively via Sequelize
    await user.destroy();
    res.status(200).json({ id: req.params.id, message: "User deleted" });
  } catch (error) {
    next(error);
  }
};

// @desc Get all users (Admin/Sub Admin only)
export const getAllUsers = async (req, res, next) => {
  try {
    const users = await User.findAll({
      attributes: { exclude: ["password"] },
      include: Role,
    });
    res.status(200).json(users);
  } catch (error) {
    next(error);
  }
};

// @desc Unlock user account (Admin only)
export const unlockUser = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    await user.update({
      lock_until: null,
      lock_count: 0,
      manual_unlock_required: false,
    });

    try {
      await sendEmail(
        user.email,
        "Account Unlocked",
        "Good news! Your account has been unlocked by our support team. You may now log in."
      );
    } catch (err) {
      console.error("Unlock email failed", err);
    }

    res.status(200).json({ message: "User account has been successfully unlocked." });
  } catch (error) {
    next(error);
  }
};
// @desc Request an OTP to unlock account
export const requestUnlock = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.account_status !== "VERIFY_REQUIRED") {
      return res.status(400).json({ message: "Account does not require verification" });
    }

    // Cooldown check (1 min)
    if (user.otp_expiry && new Date() < new Date(user.otp_expiry.getTime() - 9 * 60 * 1000)) {
       return res.status(429).json({ message: "Please wait before requesting another OTP." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = await bcrypt.hash(otp, 10);
    const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await user.update({
      otp_code: hashedOtp,
      otp_expiry: expiry,
      otp_attempts: 0
    });

    try {
      const emailHtml = getLockoutEmailTemplate({
        userName: user.name,
        otp: otp,
        unlockLink: process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/unlock` : "http://localhost:3000/unlock",
        supportLink: process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/support` : "http://localhost:3000/support",
        time: new Date().toLocaleString(),
        ipAddress: req.ip,
        companyName: "Charity Platform",
        supportEmail: process.env.EMAIL_USER || "support@charityplatform.com"
      });

      await sendEmail(
        user.email,
        "⚠️ Action Required: Unlock Your Account",
        `Your account was locked due to multiple failed login attempts.\n\nYour OTP is: ${otp}\nThis code is valid for 10 minutes.`,
        emailHtml
      );
    } catch (err) {
      console.error("Unlock OTP email failed", err);
      return res.status(500).json({ message: "Failed to send email" });
    }

    res.status(200).json({ message: "OTP sent to your email" });
  } catch (error) {
    next(error);
  }
};

// @desc Verify OTP to unlock account
export const verifyUnlock = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Please provide email and OTP" });
    }

    const user = await User.findOne({ where: { email } });

    if (!user || user.account_status !== "VERIFY_REQUIRED") {
      return res.status(400).json({ message: "Invalid request" });
    }

    if (!user.otp_code || !user.otp_expiry || new Date() > user.otp_expiry) {
      return res.status(400).json({ message: "OTP has expired. Please request a new one." });
    }

    if (user.otp_attempts >= 5) {
      return res.status(400).json({ message: "Too many failed attempts. Please request a new OTP." });
    }

    const isMatch = await bcrypt.compare(otp, user.otp_code);

    if (isMatch) {
      await user.update({
        account_status: "ACTIVE",
        lock_until: null,
        lock_count: 0,
        manual_unlock_required: false,
        otp_code: null,
        otp_expiry: null,
        otp_attempts: 0
      });

      res.status(200).json({ message: "Account unlocked successfully" });
    } else {
      await user.update({ otp_attempts: user.otp_attempts + 1 });
      res.status(400).json({ message: "Invalid OTP" });
    }
  } catch (error) {
    next(error);
  }
};
