import dotenv from "dotenv";
dotenv.config();
import connectDB from "./db/db.js";
import app from "./app.js";

connectDB()
  .then(() => {
    app.on("error", (error) => {
      console.log("Error:", error);
      throw error;
    });
    app.listen(process.env.PORT || 8000, () => {
      console.log(
        `Server is running successfully on port: ${process.env.PORT}`
      );
    });
  })
  .catch((err) => {
    console.log("MongoDb connection failed", err);
  });
