import { DataTypes } from "sequelize";
import bcrypt from "bcryptjs";
import { sequelize } from "../config/connectDB.js";
import Role from "./role.js";

// User Model Definition
const User = sequelize.define("User", {
  name: {
    type: DataTypes.STRING,
  },
  email: {
    type: DataTypes.STRING,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
  },
  lock_until: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  lock_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  },
  last_lock_time: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  manual_unlock_required: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  account_status: {
    type: DataTypes.ENUM("ACTIVE", "TEMP_LOCK", "VERIFY_REQUIRED", "SUSPICIOUS"),
    defaultValue: "ACTIVE",
  },
  otp_code: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  otp_expiry: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  otp_attempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  },
});

// 🔐 Password hash
User.beforeCreate(async (user) => {
  user.password = await bcrypt.hash(user.password, 10);
});

// 🔑 Compare password
User.prototype.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Associations
User.belongsTo(Role, { foreignKey: "role_id" });
Role.hasMany(User, { foreignKey: "role_id" });

export default User;