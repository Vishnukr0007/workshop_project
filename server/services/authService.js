import { Op } from "sequelize";
import LoginAttempt from "../models/LoginAttempt.js";
import sendEmail from "../utils/sendEmail.js";
import { getLockoutEmailTemplate } from "../utils/emailTemplates.js";

export const checkUserLock = (user) => {

  if (!user) return null;

  if (user.account_status === "VERIFY_REQUIRED" || user.manual_unlock_required) {
    console.warn(`🔒 Access denied: Account for ${user.email} requires verification.`);
    return { status: 403, message: "Account locked. Please verify to unlock." };
  }

  if (user.lock_until && new Date(user.lock_until) > new Date()) {
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
    account_status: "ACTIVE",
    lock_until: null,
    lock_count: 0,
    manual_unlock_required: false,
    otp_code: null,
    otp_expiry: null,
    otp_attempts: 0
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
      const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      let newLockCount = (user.lock_count || 0);

      // 🛡️ Only increment lock_count if this is a NEW lockout event
      // (Account wasn't already locked in the last 15 mins)
      const lastLockExpired = user.last_lock_time ? new Date(new Date(user.last_lock_time).getTime() + 15 * 60 * 1000) : null;
      if (!lastLockExpired || new Date() > lastLockExpired) {
        newLockCount += 1;
      }

      // Reset count if the last lock was more than 24 hours ago
      if (user.last_lock_time && new Date(user.last_lock_time) < twentyFourHoursAgo) {
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
        manual_unlock_required: manualUnlock,
        account_status: manualUnlock ? "VERIFY_REQUIRED" : "TEMP_LOCK"
      });

      if (manualUnlock) {
         console.error(`🚨 VERIFY_REQUIRED TRIGGERED for ${user.email} (3rd lock in 24h).`);
         
         const emailHtml = getLockoutEmailTemplate({
           userName: user.name,
           unlockLink: process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/unlock` : "http://localhost:3000/unlock",
           supportLink: process.env.CLIENT_URL ? `${process.env.CLIENT_URL}/support` : "http://localhost:3000/support",
           time: new Date().toLocaleString(),
           ipAddress: ipAddress,
           companyName: "Charity Platform",
           supportEmail: process.env.EMAIL_USER || "support@charityplatform.com"
         });

         // Non-blocking email
         sendEmail(
           user.email, 
           "⚠️ Action Required: Account Locked - Verification Required", 
           "Your account has been locked due to multiple failed login attempts.\n\nPlease use the unlock account feature to regain access.",
           emailHtml
         ).catch(err => console.error("Verify required email failed", err));

         return { 
           status: 403, 
           message: "Account locked. Please verify to unlock."
         };
      } else {
         console.warn(`🛡️ Temporary 15-minute lock triggered for ${user.email} (Lock count: ${newLockCount}).`);
         
         // Non-blocking email
         sendEmail(
           user.email, 
           "Account Temporarily Locked", 
           "Your account is temporarily locked.\n\nTry again after 15 minutes."
         ).catch(err => console.error("Temporary lock email failed", err));

         return { status: 403, message: "Your account has been blocked, try again later" };
      }
    }
  }

  // Fallback generic invalid credentials error
  return { status: 401, message: "Invalid credentials" };
};
