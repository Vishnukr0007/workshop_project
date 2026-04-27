import { DataTypes } from "sequelize";
import { sequelize } from "../config/connectDB.js";

const LoginAttempt = sequelize.define("LoginAttempt", {
  userId: {
    type: DataTypes.INTEGER,
    allowNull: true, // user may not exist
  },
  ipAddress: {
    type: DataTypes.STRING,
  },
  status: {
    type: DataTypes.ENUM("SUCCESS", "FAIL"),
  },
});

export default LoginAttempt;