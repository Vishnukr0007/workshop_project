import nodemailer from "nodemailer";

const sendEmail = async (to, subject, text, html) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT || "587"),
      secure: process.env.EMAIL_PORT === "465", // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Support Team" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
      html: html || text,
    });
    
    console.log(`📧 Email sent successfully to ${to} [Subject: ${subject}]`);
  } catch (error) {
    console.error(`❌ Email dispatch failed for ${to}:`, error.message);
    // We don't throw here to avoid breaking the main login flow if email fails
  }
};

export default sendEmail;