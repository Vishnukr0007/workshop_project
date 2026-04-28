import { Op } from "sequelize";
import LoginAttempt from "../models/LoginAttempt.js";
import sendEmail from "../utils/sendEmail.js";

export const checkUserLock = (user) => {
  if (!user) return null;

  if (user.manual_unlock_required) {
    return { status: 403, message: "Your account has been locked, please contact support" };
  }

  if (user.lock_until && user.lock_until > new Date()) {
    return { status: 403, message: "Your account has been blocked, try again later" };
  }

  return null;
};

export const checkThrottle = async (user, ipAddress) => {
  let isThrottled = false;
  const fiveMinsAgo = new Date(Date.now() - 5 * 60 * 1000);
  
  let userFailures5m = 0;
  let lastUserFailure = null;
  if (user) {
    const userFails = await LoginAttempt.findAll({
      where: { userId: user.id, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } },
      order: [['createdAt', 'DESC']]
    });
    userFailures5m = userFails.length;
    if (userFails.length > 0) lastUserFailure = userFails[0].createdAt;
  }

  const ipFails = await LoginAttempt.findAll({
    where: { ipAddress, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } },
    order: [['createdAt', 'DESC']]
  });
  const ipFailures5m = ipFails.length;
  const lastIpFailure = ipFails.length > 0 ? ipFails[0].createdAt : null;

  const maxFailures5m = Math.max(userFailures5m, ipFailures5m);
  
  if (maxFailures5m >= 5) {
    const breachCount = maxFailures5m - 4; // 5 fails = 1st breach
    const delaySeconds = 30 * Math.pow(2, breachCount - 1);
    
    // Determine the most recent failure time between user and IP
    let mostRecentFailureTime = lastIpFailure;
    if (lastUserFailure && (!lastIpFailure || lastUserFailure > lastIpFailure)) {
      mostRecentFailureTime = lastUserFailure;
    }

    if (mostRecentFailureTime) {
      const timeSinceLastFail = (Date.now() - mostRecentFailureTime.getTime()) / 1000;
      if (timeSinceLastFail < delaySeconds) {
        isThrottled = true;
      }
    }
  }
  return isThrottled;
};

export const handleLoginSuccess = async (user, ipAddress) => {
  // Reset lock fields on success
  await user.update({
    lock_until: null,
    lock_count: 0,
    manual_unlock_required: false
  });

  // Record successful login attempt
  await LoginAttempt.create({
    userId: user.id,
    ipAddress,
    status: "SUCCESS",
  });

  // Send email asynchronously
  try {
    const loginTime = new Date().toLocaleString();
    await sendEmail(
      user.email, 
      "Login Alert", 
      `You have logged in successfully.\n\nTime: ${loginTime}\nIP Address: ${ipAddress}\n\nIf this wasn't you, please change your password immediately.`
    );
  } catch (err) {
    console.error("Login email failed", err);
  }
};

export const handleLoginFailure = async (user, ipAddress) => {
  const userId = user ? user.id : null;
  
  // Record failed login attempt
  await LoginAttempt.create({
    userId,
    ipAddress,
    status: "FAIL",
  });

  // Check for 15-minute lockout (User only)
  if (user) {
    const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000);
    const userFailures15m = await LoginAttempt.count({
      where: { userId: user.id, status: "FAIL", createdAt: { [Op.gte]: fifteenMinsAgo } }
    });

    if (userFailures15m >= 10) { // Threshold hit
      const lockUntil = new Date(Date.now() + 15 * 60 * 1000);
      let newLockCount = user.lock_count + 1;
      const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      if (user.last_lock_time && user.last_lock_time < twentyFourHoursAgo) {
        newLockCount = 1;
      }

      let manualUnlock = false;
      if (newLockCount >= 3) {
         manualUnlock = true;
      }

      await user.update({
        lock_until: lockUntil,
        lock_count: newLockCount,
        last_lock_time: new Date(),
        manual_unlock_required: manualUnlock
      });

      if (manualUnlock) {
         try {
           const contactUrl = process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/contact` : "http://localhost:8000/contact";
           const htmlContent = `Your account is locked permanently.<br><br>Please <a href="${contactUrl}">contact support</a>.`;
           await sendEmail(
             user.email, 
             "Account Locked - Action Required", 
             "Your account is locked permanently.\n\nPlease contact support.", 
             htmlContent
           );
         } catch (err) {
           console.error("Manual lock email failed", err);
         }
         return { 
           status: 403, 
           message: "Your account has been locked, please contact support",
           supportUrl: process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/contact` : "http://localhost:8000/contact"
         };
      } else {
         try {
           await sendEmail(user.email, "Temporary Account Lock", "Your account is temporarily locked.\n\nTry again after 15 minutes.");
         } catch (err) {
           console.error("Temporary lock email failed", err);
         }
         return { status: 403, message: "Your account has been blocked, try again later" };
      }
    }
  }

  // Fallback generic invalid credentials error
  return { status: 401, message: "Invalid credentials" };
};
