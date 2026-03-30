import jwt from "jsonwebtoken";

export const generateTokenAndSetCookie = (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("token", token, {
    httpOnly: true,  // this can not access by javascript and prevent by XSS  attack 
    secure: process.env.NODE_ENV === "production", // in locathost http and in production we have https(more secure) 
    sameSite: "strict",   // prevent csrf attack 
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return token; 
};
