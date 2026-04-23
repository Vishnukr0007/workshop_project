import jwt from "jsonwebtoken"; 
import User from "../models/user.js";
import Role from "../models/role.js";
import sendEmail from "../utils/sendEmail.js";

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

    // Search user and include their Role
    const user = await User.findOne({
      where: { email },
      include: Role,
    });

    if (user && (await user.matchPassword(password))) {
      // Send email asynchronously
      try {
        await sendEmail(
          user.email, 
          "Login Alert", 
          "You successfully logged in to your account. If this wasn't you, please reset your password immediately."
        );
      } catch (err) {
        console.error("Login email failed", err);
      }

      res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        token: generateToken(user),
      });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
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