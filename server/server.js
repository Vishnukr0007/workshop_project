import express from "express";
import dotenv from "dotenv";
import connectDB, { sequelize } from "./config/connectDB.js";
import userRouter from "./routes/userRoutes.js";
import { errorHandler } from "./middleware/errorMiddleware.js";

// Load env vars
dotenv.config();

const app = express();

// Body parser middleware
app.use(express.json());

// Connect to the database
await connectDB();
  
// Sync models (creates tables if they don't exist)
await sequelize.sync();

// Mount routers
app.use("/api/users", userRouter);

app.get("/", (req, res) => {
  res.send("API Running...");
});

app.use(errorHandler);

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log("✅ Server running on port", port);
});