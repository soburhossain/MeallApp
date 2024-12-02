//IMPORTING REQUIRED MODULES:
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bodyParser from "body-parser";
import moment from "moment-timezone";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import emailValidator from "email-validator"; // Install this package using `npm install email-validator`
dotenv.config();
const app = express();
app.use(cors());
app.use(bodyParser.json());
// Email configuration
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
// MongoDB Models
const amanatHallMemberSchema = new mongoose.Schema({
  name: String,
  email: String,
  token: String,
  password: String,
  verificationCode: String,
  depositedAmount: Number,
});
const amanatMealHistorySchema = new mongoose.Schema({
  date: String,
  totalLunch: Number,
  totalDinner: Number,
  users: [
    {
      email: String,
      name: String,
      token: String,
      lunch: Boolean,
      dinner: Boolean,
    },
  ],
});
//Pending User Model
const pendingUserSchema = new mongoose.Schema({
  name: String,
  email: String,
  token: String,
  password: String,
  verificationCode: String, // Already hashed
  requestedAt: { type: Date, default: Date.now },
});
const PendingUser = mongoose.model("PendingUser", pendingUserSchema);
const AmanatHallMember = mongoose.model(
  "AmanatHallMember",
  amanatHallMemberSchema
);
const AmanatMealHistory = mongoose.model(
  "AmanatMealHistory",
  amanatMealHistorySchema
);

// Helper function to get the next date (for meal updates) considering Dhaka time zone
const getNextDate = () => {
  return moment().tz("Asia/Dhaka").add(1, "days").format("YYYY-MM-DD"); // Get the next day in Dhaka timezone
};

// CONNECTING TO MONGODB ATLAS:
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.log("MongoDB connection failed", err);
    process.exit(1); // Exit process if MongoDB connection fails
  });
// Middleware to ensure daily initialization for all users
app.use(async (req, res, next) => {
  try {
    await initializeDailyMealHistory();
    next(); // Proceed to the next middleware or route
  } catch (error) {
    res
      .status(500)
      .json({ message: "Failed to initialize daily meal history" });
  }
});

// Utility function to get current date in 'YYYY-MM-DD' format
const getCurrentDate = () => {
  const today = moment.tz("Asia/Dhaka");
  return today.format("YYYY-MM-DD");
};
// Utility function to ensure all users are added to today's meal history
const initializeDailyMealHistory = async () => {
  const currentDate = getNextDate();
  // Check if meal history already exists for today
  let mealHistory = await AmanatMealHistory.findOne({ date: currentDate });
  // If not, create it and include all users
  if (!mealHistory) {
    const allUsers = await AmanatHallMember.find(); // Fetch all registered users
    // Prepare the users array with lunch and dinner set to true
    const users = allUsers.map((user) => ({
      email: user.email,
      name: user.name,
      token: user.token,
      lunch: true,
      dinner: true,
    }));
    // Create and save the new meal history
    mealHistory = new AmanatMealHistory({
      date: currentDate,
      totalLunch: users.length, // All users have lunch enabled
      totalDinner: users.length, // All users have dinner enabled
      users,
    });

    await mealHistory.save();
  }
  return mealHistory;
};
//Requesting or a request by a new user:
app.post("/register-request", async (req, res) => {
  const { name, email, token, password } = req.body;
  // Check if all required fields are filled
  if (!name || !email || !token || !password) {
    return res.status(400).json({ message: "All the fields are required!" });
  }

  // Validate name (less than 16 characters)
  if (name.length > 15) {
    return res
      .status(400)
      .json({ message: "Name must be less than 16 characters!" });
  }

  // Validate password (at least 8 characters)
  if (password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters!" });
  }

  // Validate email format
  if (!emailValidator.validate(email)) {
    return res.status(400).json({ message: "Invalid email format!" });
  }

  // Check if the email belongs to a Google domain (Gmail, GoogleMail)
  const emailDomain = email.split("@")[1];
  if (emailDomain !== "gmail.com" && emailDomain !== "googlemail.com") {
    return res
      .status(400)
      .json({ message: "Please use a valid Gmail address!" });
  }

  try {
    // Check if user already exists
    const existingUser = await AmanatHallMember.findOne({ token });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Add the request to the PendingUser collection
    const pendingUser = new PendingUser({
      name,
      email,
      token,
      password: hashedPassword,
    });

    await pendingUser.save();

    res
      .status(200)
      .json({ message: "Registration request submitted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get all pending user registration requests
app.get("/admin/pending-users", async (req, res) => {
  try {
    const pendingUsers = await PendingUser.find();
    res.status(200).json(pendingUsers);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/delete-pending-user", async (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res
      .status(400)
      .json({ message: "Name is required to delete a user." });
  }

  try {
    const deletedUser = await PendingUser.findOneAndDelete({ name });

    if (!deletedUser) {
      return res
        .status(404)
        .json({ message: "No pending user found with this name." });
    }

    res
      .status(200)
      .json({ message: `Pending user ${name} deleted successfully.` });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Server error while deleting pending user." });
  }
});

// Register new user
app.post("/register", async (req, res) => {
  const { name, email, token, password } = req.body;
  if (!name || !email || !token || !password) {
    return res
      .status(400)
      .json({ message: "Please fill up all the required fields!" });
  }

  try {
    const existingUser = await AmanatHallMember.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const newUser = new AmanatHallMember({
      name,
      email,
      token,
      password,
      depositedAmount: 0,
    });
    await newUser.save();
    const mealHistory = await initializeDailyMealHistory();
    mealHistory.users.push({
      email,
      name,
      token,
      lunch: true,
      dinner: true,
    });

    mealHistory.totalLunch = mealHistory.users.filter((u) => u.lunch).length;
    mealHistory.totalDinner = mealHistory.users.filter((u) => u.dinner).length;
    await mealHistory.save();
    // Remove the approved user from PendingUser collection
    await PendingUser.findOneAndDelete({ email });

    res.status(200).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Update meal (Lunch/Dinner)
// Update meal (Lunch/Dinner)
app.post("/update-meal", async (req, res) => {
  const { password, token, lunch, dinner } = req.body;

  if (!password || !token) {
    return res.status(400).json({ message: "Password and token are required" });
  }

  try {
    const user = await AmanatHallMember.findOne({ token });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Check if the provided password matches the user's password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid Password or token" });
    }

    // Get the next day's date for meal updates
    const nextDate = getNextDate();

    // Fetch the meal history for the next day
    let mealHistory = await AmanatMealHistory.findOne({ date: nextDate });

    // If no meal history exists for the next day, create a new one
    if (!mealHistory) {
      mealHistory = new AmanatMealHistory({
        date: nextDate,
        totalLunch: 0,
        totalDinner: 0,
        users: [],
      });
    }

    // Check if lunch or dinner is available for the next day (this logic assumes availability is based on total counts)
    const lunchAvailable = mealHistory.totalLunch > 0;
    const dinnerAvailable = mealHistory.totalDinner > 0;

    // If the user wants lunch and it's not available, show an error
    if (lunch && !lunchAvailable) {
      return res
        .status(400)
        .json({ message: "No lunch available for the next day" });
    }

    // If the user wants dinner and it's not available, show an error
    if (dinner && !dinnerAvailable) {
      return res
        .status(400)
        .json({ message: "No dinner available for the next day" });
    }

    // Check if the user has already updated their meal preferences for the next day
    const userMeal = mealHistory.users.find((u) => u.token === token);

    if (userMeal) {
      // Update the user's meal preferences for the next day
      userMeal.lunch = lunch;
      userMeal.dinner = dinner;
    } else {
      // Add the user's meal preferences for the next day
      mealHistory.users.push({ token, name: user.name, lunch, dinner });
    }

    // Recalculate the totals after the user's meal status is updated
    mealHistory.totalLunch = mealHistory.users.filter((u) => u.lunch).length;
    mealHistory.totalDinner = mealHistory.users.filter((u) => u.dinner).length;

    // Save the updated meal history for the next day
    await mealHistory.save();

    res
      .status(200)
      .json({ message: "Meal updated successfully for the next day" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
// Admin Panel: Get all users
app.get("/admin/users", async (req, res) => {
  try {
    const users = await AmanatHallMember.find();
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
// Admin Panel: Update user deposit amount
app.post("/admin/update-deposit", async (req, res) => {
  const { token, depositedAmount } = req.body;
  try {
    if (!token || !depositedAmount) {
      return res.status(400).json({ message: "Please fill the form!" });
    }
    const user = await AmanatHallMember.findOne({ token });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    user.depositedAmount =
      Number(user.depositedAmount) + Number(depositedAmount);
    await user.save();
    res.status(200).json({ message: "Deposit updated successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Admin Panel: Get meal history
app.get("/admin/meal-history", async (req, res) => {
  try {
    const mealHistory = await AmanatMealHistory.find();
    res.status(200).json(mealHistory);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Admin Panel: Calculate total cost for meals
app.post("/admin/calculate-total-cost", async (req, res) => {
  const { mealRate } = req.body; // Assuming mealRate comes from the request
  try {
    const mealHistory = await AmanatMealHistory.find();
    let totalCost = 0;
    mealHistory.forEach((history) => {
      totalCost +=
        history.totalLunch * mealRate + history.totalDinner * mealRate;
    });
    res.status(200).json({ totalCost });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
// Admin Panel: Calculate meal rate from total cost
// Admin Panel: Calculate meal rate from total cost
app.post("/admin/calculate-meal-rate", async (req, res) => {
  const { totalCost } = req.body; // Assuming totalCost comes from the request
  try {
    // Fetch all meal history records
    const mealHistory = await AmanatMealHistory.find();

    let totalMeals = 0;
    // Loop through each meal history and sum up the total meals
    mealHistory.forEach((history) => {
      totalMeals += history.totalLunch + history.totalDinner;
    });

    // If there are no meals, return an error
    if (totalMeals === 0) {
      return res
        .status(400)
        .json({ message: "No meals found to calculate rate" });
    }

    // Calculate the meal rate by dividing total cost by total meals
    const mealRate = totalCost / totalMeals;
    res.status(200).json({ mealRate });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Admin Panel: Get user meal details and payment calculations

app.get("/admin/user-payment-details", async (req, res) => {
  const totalMealCost = parseFloat(req.query.totalMealCost); // Get totalCost from the query parameter
  // Total cost input from the frontend

  try {
    const users = await AmanatHallMember.find();
    const mealHistory = await AmanatMealHistory.find();

    // Calculate total meals consumed across all users
    let totalMeals = 0;
    mealHistory.forEach((history) => {
      totalMeals += history.totalLunch + history.totalDinner;
    });

    // If no meals are recorded, return an error
    if (totalMeals === 0) {
      return res
        .status(400)
        .json({ message: "No meals found to calculate payment details" });
    }
    // Calculate meal rate
    const mealRate = Number(totalMealCost / totalMeals).toFixed(3);
    // Calculate payment details for each user
    const userPayments = users.map((user) => {
      const userTotalMeals = mealHistory.reduce((sum, history) => {
        const userMeals = history.users.find((u) => u.email === user.email);
        if (userMeals) {
          sum += (userMeals.lunch ? 1 : 0) + (userMeals.dinner ? 1 : 0);
        }
        return sum;
      }, 0);
      // Ensure depositedAmount is available
      const depositedAmount = user.depositedAmount || 0; // Fallback to 0 if not set
      const totalPayable = userTotalMeals * mealRate;
      const dueAmount = totalPayable - depositedAmount;

      return {
        name: user.name,
        email: user.email,
        token: user.token,
        totalMeals: userTotalMeals,
        depositedAmount: depositedAmount,
        totalPayable,
        dueAmount: Number(dueAmount).toFixed(3), // Keep 3 decimal places
        mealRate: Number(mealRate).toFixed(3), // Include meal rate for reference
      };
    });

    res.status(200).json(userPayments);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
// Admin Panel: Delete all data and reset meal history
app.delete("/admin/reset-data", async (req, res) => {
  try {
    // Get the current date in Dhaka timezone
    const currentDate = moment().tz("Asia/Dhaka").format("YYYY-MM-DD"); // Current date
    const nextDate = moment(currentDate).add(1, "days").format("YYYY-MM-DD"); // Calculate next day

    // Reset the depositedAmount to 0 for all users in the AmanatHallMember collection
    await AmanatHallMember.updateMany({}, { $set: { depositedAmount: 0 } });

    // Delete meal history records for both the current date and the next date
    await AmanatMealHistory.deleteMany({
      $or: [{ date: currentDate }, { date: nextDate }],
    });

    // Delete all records from the PendingUser collection
    await PendingUser.deleteMany({});

    res.status(200).json({
      message: `Data has been reset. Deposited amount is now 0 for all users, and meal history for ${currentDate} and ${nextDate} has been deleted.`,
    });
  } catch (error) {
    console.error("Error resetting data:", error);
    res.status(500).json({ message: "Failed to reset data" });
  }
});
// Admin Panel: Delete user by Email number and token
app.delete("/admin/delete-user", async (req, res) => {
  const { email, token } = req.body;

  if (!email || !token) {
    return res.status(400).json({ message: "Email and token are required" });
  }

  try {
    // Find the user in AmanatHallMember collection
    const user = await AmanatHallMember.findOne({ email, token });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Delete the user from AmanatHallMember collection
    await AmanatHallMember.deleteOne({ email, token });

    // Remove the user from today's meal history in AmanatMealHistory
    const currentDate = getCurrentDate();
    let mealHistory = await AmanatMealHistory.findOne({ date: currentDate });
    if (mealHistory) {
      // Remove the user from the meal history
      mealHistory.users = mealHistory.users.filter(
        (user) => user.email !== email
      );

      // Update the meal history totals
      mealHistory.totalLunch = mealHistory.users.filter((u) => u.lunch).length;
      mealHistory.totalDinner = mealHistory.users.filter(
        (u) => u.dinner
      ).length;
      await mealHistory.save();
    }

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, token, password } = req.body;
  if (!email || !token || !password) {
    return res
      .status(400)
      .json({ message: "Please provide email, token, and password" });
  }
  try {
    // Find user by email and token
    const user = await AmanatHallMember.findOne({ email, token });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    // Compare password with hashed password in database
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid password" });
    }
    // Generate a JWT token
    const authToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);

    res.status(200).json({ message: "Login successful", token: authToken });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
// Get unique dates and their corresponding meal data
app.get("/unique-dates-with-meal-status", async (req, res) => {
  try {
    // Fetch all records and group them by date
    const mealHistories = await AmanatMealHistory.aggregate([
      {
        $group: {
          _id: "$date", // Group by date
          users: { $first: "$users" }, // Get the users for each date
        },
      },
      { $sort: { _id: 1 } }, // Sort dates in ascending order
    ]);

    // Format the data for frontend
    const formattedData = mealHistories.map((entry) => ({
      date: entry._id,
      users: entry.users,
    }));
    res.status(200).json(formattedData);
    const data = await AmanatMealHistory.find();
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get the token from the Authorization header

  if (!token) {
    return res.status(401).json({ message: "Authorization required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await AmanatHallMember.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      name: user.name,
      email: user.email,
      token: user.token,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Send reset code
app.post("/send-code", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await AmanatHallMember.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });
    // Generate a random 6-digit code
    const resetCode = crypto.randomInt(100000, 999999).toString();
    user.verificationCode = resetCode;
    await user.save();
    // Send email
    await transporter.sendMail({
      to: email,
      subject: "Password Reset Code for MessMealApp",
      text: `Your password reset code is ${resetCode}`,
    });
    res.send({ message: "Reset code sent to your email" });
  } catch (error) {
    res.status(500).send({ message: "Error sending reset code" });
  }
});
// Verify code and change password
app.post("/verify-code", async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!newPassword)
    return res.status(400).json({ message: "Please enter a new password" });
  try {
    const user = await AmanatHallMember.findOne({ email });
    if (!user || user.verificationCode !== code)
      return res.status(400).send({ message: "Invalid code" });
    // Hash and update the password
    user.password = await bcrypt.hash(newPassword, 10);
    user.verificationCode = null; // Clear token after successful reset
    await user.save();
    res.send({ message: "Password changed successfully" });
  } catch (error) {
    res.status(500).send({ message: "Error verifying code" });
  }
});

// Resend code
app.post("/resend-code", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await AmanatHallMember.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });

    // Generate a new reset code
    const resetCode = crypto.randomInt(100000, 999999).toString();
    user.verificationCode = resetCode;
    await user.save();
    // Send email
    await transporter.sendMail({
      to: email,
      subject: "Password Reset Code for MessMealApp",
      text: `Your password reset code is ${resetCode}`,
    });

    res.send({ message: "Reset code resent to your email" });
  } catch (error) {
    res.status(500).send({ message: "Error resending reset code" });
  }
});
app.post("/request-verification", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  // Generate a new verification code
  const verificationCode = crypto.randomInt(100000, 999999).toString();

  try {
    // Check if a PendingUser with the email already exists
    const existingUser = await PendingUser.findOne({ email });

    if (existingUser) {
      // Update the existing user's verification code
      existingUser.verificationCode = verificationCode;
      await existingUser.save();
    } else {
      // Create a new PendingUser if not exists
      const pendingUser = new PendingUser({
        email,
        verificationCode,
      });
      await pendingUser.save();
    }

    // Send email using Nodemailer
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Verification Code",
      text: `Your verification code is: ${verificationCode}`,
    });

    res.status(200).json({ message: "Verification code sent to your email." });
  } catch (error) {
    res.status(500).json({ message: "Error sending verification code." });
  }
});
app.post("/verify-and-register", async (req, res) => {
  const { email, verificationCode, name, password, token } = req.body;

  // Input validation
  if (!email || !verificationCode || !name || !password || !token) {
    return res.status(400).json({ message: "All fields are required." });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long." });
  }

  try {
    const pendingUser = await PendingUser.findOne({ email });
    if (!pendingUser || pendingUser.verificationCode !== verificationCode) {
      return res.status(400).json({ message: "Invalid verification code." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    // Clear verificationCode and save complete user details
    pendingUser.verificationCode = null;
    pendingUser.name = name;
    pendingUser.password = hashedPassword; // Ideally, hash the password
    pendingUser.token = token;
    await pendingUser.save();

    res.status(200).json({ message: "Registration request is sent" });
  } catch (error) {
    res.status(500).json({ message: "Error verifying and registering user." });
  }
});
// Route to toggle lunch and/or dinner status for the current date
app.put("/toggle-meals", async (req, res) => {
  const { lunchStatus, dinnerStatus } = req.body; // lunchStatus and dinnerStatus: true/false

  if (typeof lunchStatus !== "boolean" || typeof dinnerStatus !== "boolean") {
    return res
      .status(400)
      .json({ message: "Invalid status provided for lunch or dinner" });
  }
  // Get current date in Dhaka timezone and calculate the next day
  const currentDate = moment().tz("Asia/Dhaka").format("YYYY-MM-DD");
  const nextDate = moment(currentDate).add(1, "days").format("YYYY-MM-DD"); // Get the next day

  try {
    // Check if meal history for the next date already exists
    let mealHistory = await AmanatMealHistory.findOne({ date: nextDate });
    console.log(mealHistory);

    if (mealHistory) {
      // Update the lunch and/or dinner status for all users
      mealHistory.users.forEach((user) => {
        if (lunchStatus !== undefined) user.lunch = lunchStatus;
        if (dinnerStatus !== undefined) user.dinner = dinnerStatus;
      });

      // Recalculate totalLunch and totalDinner based on the updated users array
      mealHistory.totalLunch = mealHistory.users.filter(
        (user) => user.lunch
      ).length;
      mealHistory.totalDinner = mealHistory.users.filter(
        (user) => user.dinner
      ).length;
    } else {
      // If no meal history exists for the next day, create a new one
      const registeredUsers = await AmanatHallMember.find().lean(); // Ensure fresh data

      if (registeredUsers.length === 0) {
        console.error("No users found in the database!");
        return res
          .status(404)
          .json({ message: "No users found in the database" });
      }

      // Log each registered user to verify the fields
      registeredUsers.forEach((user) => {});

      // Map the registered users into the format expected by the mealHistory
      const users = registeredUsers.map((user) => ({
        email: user.email,
        name: user.name,
        token: user.token,
        lunch: lunchStatus, // Use the provided lunch status
        dinner: dinnerStatus, // Use the provided dinner status
      }));

      // Calculate totalLunch and totalDinner based on the provided statuses
      const totalLunch = users.filter((user) => user.lunch).length;
      const totalDinner = users.filter((user) => user.dinner).length;

      // Create a new meal history record with all users
      mealHistory = new AmanatMealHistory({
        date: nextDate,
        totalLunch: totalLunch, // Set totalLunch based on users with lunchStatus
        totalDinner: totalDinner, // Set totalDinner based on users with dinnerStatus
        users: users, // Add all users with their meal status
      });
    }
    // Log the meal history before saving
    // Save the updated or new meal history record for the next day
    await mealHistory.save();
    res
      .status(200)
      .json({ message: "Meal status updated successfully for the next day" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
