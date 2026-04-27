import jwt from "jsonwebtoken"; 
import User from "../models/user.js";
import Role from "../models/role.js";
import sendEmail from "../utils/sendEmail.js";
import LoginAttempt from "../models/LoginAttempt.js";
import { Op } from "sequelize";

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

    // Search user and include their Role
    const user = await User.findOne({
      where: { email },
      include: Role,
    });

    // --- 1. PRE-CHECKS (Throttling & Lockouts) BEFORE PASSWORD VALIDATION ---
    
    // Check Escalation & Temporary Lockout
    if (user) {
      if (user.manual_unlock_required) {
        return res.status(403).json({ message: "Your account has been locked, please contact support" });
      }
      if (user.lock_until && user.lock_until > new Date()) {
        return res.status(403).json({ message: "Your account has been blocked, try again later" });
      }
    }

    // Check Throttling (Progressive Delay)
    const fiveMinsAgo = new Date(Date.now() - 5 * 60 * 1000);
    
    let userFailures5m = 0;
    let lastUserFailure = null;
    if (user) {
      const userFails = await LoginAttempt.findAll({
        where: { userId: user.id, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } },
        order: [['createdAt', 'DESC']]
      });
      userFailures5m = userFails.length;
      if (userFails.length > 0) lastUserFailure = userFails[0].createdAt;
    }

    const ipFails = await LoginAttempt.findAll({
      where: { ipAddress, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } },
      order: [['createdAt', 'DESC']]
    });
    const ipFailures5m = ipFails.length;
    const lastIpFailure = ipFails.length > 0 ? ipFails[0].createdAt : null;

    const maxFailures5m = Math.max(userFailures5m, ipFailures5m);
    
    if (maxFailures5m >= 5) {
      const breachCount = maxFailures5m - 4; // 5 fails = 1st breach
      const delaySeconds = 30 * Math.pow(2, breachCount - 1);
      
      // Determine the most recent failure time between user and IP
      let mostRecentFailureTime = lastIpFailure;
      if (lastUserFailure && (!lastIpFailure || lastUserFailure > lastIpFailure)) {
        mostRecentFailureTime = lastUserFailure;
      }

      if (mostRecentFailureTime) {
        const timeSinceLastFail = (Date.now() - mostRecentFailureTime.getTime()) / 1000;
        if (timeSinceLastFail < delaySeconds) {
          return res.status(429).json({ message: "Your account has been blocked, try again later" });
        }
      }
    }

    // --- 2. PASSWORD VALIDATION ---
    if (user && (await user.matchPassword(password))) {
      // Reset lock fields on success
      await user.update({
        lock_until: null,
        lock_count: 0,
        manual_unlock_required: false
      });

      // Record successful login attempt
      await LoginAttempt.create({
        userId: user.id,
        ipAddress,
        status: "SUCCESS",
      });

      // Send email asynchronously
      try {
        const loginTime = new Date().toLocaleString();
        await sendEmail(
          user.email, 
          "Login Alert", 
          `You have logged in successfully.\n\nTime: ${loginTime}\nIP Address: ${ipAddress}\n\nIf this wasn't you, please change your password immediately.`
        );
      } catch (err) {
        console.error("Login email failed", err);
      }

      return res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        token: generateToken(user),
      });
    } else {
      // --- 3. HANDLE FAILED LOGIN ---
      const userId = user ? user.id : null;
      await LoginAttempt.create({
        userId,
        ipAddress,
        status: "FAIL",
      });

      // Check for 15-minute lockout (User only)
      if (user) {
        const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000);
        const userFailures15m = await LoginAttempt.count({
          where: { userId: user.id, status: "FAIL", createdAt: { [Op.gte]: fifteenMinsAgo } }
        });

        if (userFailures15m >= 10) { // Threshold hit
          const lockUntil = new Date(Date.now() + 15 * 60 * 1000);
          let newLockCount = user.lock_count + 1;
          const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
          
          if (user.last_lock_time && user.last_lock_time < twentyFourHoursAgo) {
            newLockCount = 1;
          }

          let manualUnlock = false;
          if (newLockCount >= 3) {
             manualUnlock = true;
          }

          await user.update({
            lock_until: lockUntil,
            lock_count: newLockCount,
            last_lock_time: new Date(),
            manual_unlock_required: manualUnlock
          });

          if (manualUnlock) {
             try {
               await sendEmail(user.email, "Account Locked - Action Required", "Your account is locked permanently.\n\nPlease contact support.");
             } catch (err) {
               console.error("Manual lock email failed", err);
             }
             return res.status(403).json({ message: "Your account has been locked, please contact support" });
          } else {
             try {
               await sendEmail(user.email, "Temporary Account Lock", "Your account is temporarily locked.\n\nTry again after 15 minutes.");
             } catch (err) {
               console.error("Temporary lock email failed", err);
             }
             return res.status(403).json({ message: "Your account has been blocked, try again later" });
          }
        }
      }

      return res.status(401).json({ message: "Invalid credentials" });
    }
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