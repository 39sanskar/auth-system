
import { MailtrapClient } from "mailtrap";
import dotenv from "dotenv";

dotenv.config();

// console.log("TOKEN:", process.env.MAILTRAP_TOKEN); // for debugging 

export const mailtrapClient = new MailtrapClient({
	// endpoint: process.env.MAILTRAP_ENDPOINT,
	token: process.env.MAILTRAP_TOKEN,
  
});

export const sender = {
	email: "hello@demomailtrap.co",
	name: "Sanskar",
};

