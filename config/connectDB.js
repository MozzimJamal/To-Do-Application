import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

// check env
if (!process.env.MONGODB_URI) {
  throw new Error("❌ Please provide MONGODB_URI in the .env file");
}

async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log("✅ MongoDB connected:", process.env.MONGODB_URI);
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    process.exit(1);
  }
}

export default connectDB;
