import mongoose from "mongoose";
export const connectDB = async () => {
  try {

    // console.log("MONGO_URI:", process.env.MONGO_URI); // debug

    const conn = await mongoose.connect(process.env.MONGO_URI)
    console.log(`MongoDB Connected Successfully: ${conn.connection.host}`)
  } catch (error) {
    console.log("Error connection to MongoDB: ", error.message);
    process.exit(1); // 1 is failure, 0 status code is success 
  }
}; 
