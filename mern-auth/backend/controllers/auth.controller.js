import bcryptjs from "bcryptjs";
import crypto from "crypto";


import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { User } from "../models/user.model.js";

import {
  sendPasswordResetEmail,
	sendResetSuccessEmail,
	sendVerificationEmail,
  sendWelcomeEmail,
} from "../mailtrap/emails.js";


export const signup = async (req, res) => {
  
  const { email, password, name } = req.body;

  try {
    if (!email || !password | !name) {
      throw new Error("All fields are required");
    }

    const userAlreadyExists = await User.findOne({ email });
    // console.log("userAlreadyExists: ", userAlreadyExists);   // Debug step 

    if (userAlreadyExists) {
      return res.status(400).json({
        success: false,
        message: "User already exists"
      })
    }

    // hash-password
    const hashPassword = await bcryptjs.hash(password, 10);

    // give us verification token randomly
    const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();

    // create a new user 
    const user = new User({
      email,
      password: hashPassword,
      name,
      verificationToken,
      verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours 
    });

    await user.save();

    // jwt
    generateTokenAndSetCookie(res, user._id);

    await sendVerificationEmail(user.email, verificationToken);

    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        ...user._doc,
        password: undefined 
      },
    }); 

  } catch (error) {
    res.status(400).json({ success: false, message: error.message }); 
  }
  
}; 

// verifyEmail function 
export const verifyEmail = async (req, res) => {

  const { code } = req.body;
  try {
    const user = await User.findOne({
      verificationToken: code,
      verificationTokenExpiresAt: { $gt: Date.now() } // make sure that token is not expire 
    })

    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid or expired verification code."})
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;
    await user.save();

    await sendWelcomeEmail(user.email, user.name);

    res.status(200).json({
      success: true,
      message: "Email verified Successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    })
  } catch (error) {
    console.log("Error in verifyEmail ", error);
    res.status(500).json({ success: false, message: "Server error" })
  }
}

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credientials"
      });
    }

    const isPasswordValid = await bcryptjs.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      }); 
    }

    generateTokenAndSetCookie(res, user._id);

    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      user: {
        ...user._doc,
        password: undefined, 
      },
    });
  } catch (error) {
    console.log("Error in login", error);
    res.status(400).json({ success: false, message: error.message });
  }
}

export const logout = (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ success: true, message: "Logged out Successfully" });
}

export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ success: false, message: "User not found" }); 
    }

    // Generate reset Token
    const  resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiresAt = Date.now() + 1 * 60 * 60 * 1000; // expires after 1 hour 

    // save in the database 
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = resetTokenExpiresAt;

    // save the user in databse 
    await user.save();

    // send email
    await sendPasswordResetEmail(user.email, `${process.env.CLIENT_URL}/reset-password/${resetToken}`); 

    res.status(200).json({ success: true, message: "Password reset link sent to your email" }); 
  } catch (error) {
    console.log("Error in forgotPassword ", error);
    res.status(400).json({ success: false, message: error.message });
  }
}; 

export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;   // we call here token because it is defined in token as the route.
    const { password } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiresAt: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid or expired reset token" });
    }

    // update password 
    const hashedPassword = await bcryptjs.hash(password, 10);

    user.password = hashedPassword; 
    // just updated the password we can delete these fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpiresAt = undefined;
    await user.save();    // save in the database 

    await sendResetSuccessEmail(user.email);

    res.status(200).json({ success: true, message: "Password reset successful" });
  } catch (error) {
    console.log("Error in resetPassword", error);
    res.status(400).json({ success: true, message: error.message });
  }
};

// check-auth 
export const checkAuth = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");

    if (!user) {
      return res.status(400).json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, user: {
      ...user._doc,
      password: undefined 
    }});

  } catch (error) {
    console.log("Error is checkAuth ", error);
    res.status(400).json({ success: false, message: error.message });
  }
}

