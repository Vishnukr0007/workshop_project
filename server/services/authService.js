import { Op } from "sequelize";
import LoginAttempt from "../models/LoginAttempt.js";
import sendEmail from "../utils/sendEmail.js";

export const checkUserLock = (user) => {
  if (!user) return null;

  if (user.manual_unlock_required) {
    console.warn(`🔒 Access denied: Account for ${user.email} is permanently locked (Scenario 4).`);
    return { status: 403, message: "Your account has been locked, please contact support" };
  }

  if (user.lock_until && user.lock_until > new Date()) {
    console.warn(`⏳ Access denied: Account for ${user.email} is temporarily blocked.`);
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
    userFailures5m = await LoginAttempt.count({
      where: { userId: user.id, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } }
    });
    if (userFailures5m > 0) {
      const lastFail = await LoginAttempt.findOne({
        where: { userId: user.id, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } },
        order: [['createdAt', 'DESC']]
      });
      lastUserFailure = lastFail?.createdAt;
    }
  }

  const ipFailures5m = await LoginAttempt.count({
    where: { ipAddress, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } }
  });
  
  let lastIpFailure = null;
  if (ipFailures5m > 0) {
    const lastFail = await LoginAttempt.findOne({
      where: { ipAddress, status: "FAIL", createdAt: { [Op.gte]: fiveMinsAgo } },
      order: [['createdAt', 'DESC']]
    });
    lastIpFailure = lastFail?.createdAt;
  }

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
        console.warn(`⚠️ Throttling active for IP/User. Delay required: ${Math.round(delaySeconds)}s`);
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

  // Fire-and-forget email (non-blocking)
  console.log(`✅ Login success for ${user.email}. Resetting failure counters.`);
  const loginTime = new Date().toLocaleString();
  sendEmail(
    user.email, 
    "Login Alert", 
    `You have logged in successfully.\n\nTime: ${loginTime}\nIP Address: ${ipAddress}\n\nIf this wasn't you, please change your password immediately.`
  ).catch(err => console.error("Login email failed", err));
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
      let newLockCount = (user.lock_count || 0) + 1;
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
         console.error(`🚨 PERMANENT LOCK TRIGGERED for ${user.email} (3rd lock in 24h).`);
         const contactUrl = process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/contact` : "http://localhost:8000/contact";
         const htmlContent = `Your account is locked permanently.<br><br>Please <a href="${contactUrl}">contact support</a>.`;
         
         // Non-blocking email
         sendEmail(
           user.email, 
           "Account Locked - Action Required", 
           "Your account is locked permanently.\n\nPlease contact support.", 
           htmlContent
         ).catch(err => console.error("Manual lock email failed", err));

         return { 
           status: 403, 
           message: "Your account has been locked, please contact support",
           supportUrl: contactUrl
         };
      } else {
         console.warn(`🛡️ Temporary 15-minute lock triggered for ${user.email} (Failure count: ${newLockCount}).`);
         
         // Non-blocking email
         sendEmail(
           user.email, 
           "Temporary Account Lock", 
           "Your account is temporarily locked.\n\nTry again after 15 minutes."
         ).catch(err => console.error("Temporary lock email failed", err));

         return { status: 403, message: "Your account has been blocked, try again later" };
      }
    }
  }

  // Fallback generic invalid credentials error
  return { status: 401, message: "Invalid credentials" };
};
