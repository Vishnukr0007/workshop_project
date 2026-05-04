export const getLockoutEmailTemplate = ({ userName, otp, unlockLink, supportLink, time, ipAddress, companyName, supportEmail }) => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333; line-height: 1.6;">
      <div style="text-align: center; padding: 20px 0;">
        <h2 style="color: #d9534f; margin: 0;">⚠️ Security Alert</h2>
      </div>
      
      <p>Hi ${userName || "User"},</p>
      
      <p>We detected unusual activity on your account and, as a precaution, access has been temporarily restricted.</p>
      
      <div style="background: #f9f9f9; padding: 15px; border-left: 4px solid #d9534f; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #d9534f;">🔒 What this means</h3>
        <p style="margin-bottom: 0;">Your account has been secured to protect your information. You won't be able to sign in until it's verified.</p>
      </div>
      
      <h3 style="margin-top: 30px;">👉 What you should do next</h3>
      <p>Please verify your identity to restore access:</p>
      
      <h4>Option 1: Unlock your account (recommended)</h4>
      ${otp ? `
      <p>Use the following One-Time Password (OTP) to unlock your account. <strong>This code is valid for 10 minutes.</strong></p>
      <div style="text-align: center; margin: 20px 0;">
        <span style="font-size: 24px; font-weight: bold; letter-spacing: 4px; padding: 10px 20px; background: #eee; border-radius: 4px;">${otp}</span>
      </div>
      <p>Or click the secure link below to proceed to the unlock page:</p>
      ` : `
      <p>Click the secure link below to proceed to the unlock page and request your One-Time Password (OTP):</p>
      `}
      <div style="text-align: center; margin: 25px 0;">
        <a href="${unlockLink}" style="
          display:inline-block;
          padding:12px 24px;
          background:#d9534f;
          color:white;
          text-decoration:none;
          border-radius:6px;
          font-weight:bold;
        ">
          Unlock My Account
        </a>
      </div>
      
      <h4>Option 2: Contact Support</h4>
      <p>If you're unable to access the link or use the OTP, our support team can help:<br>
      <a href="${supportLink}" style="color: #0066cc;">${supportLink}</a></p>
      
      <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
      
      <h3 style="color: #555;">🛡️ Security Tips</h3>
      <ul style="color: #666; font-size: 14px;">
        <li>If this activity wasn't you, change your password immediately after unlocking.</li>
        <li>Never share your OTP or password with anyone.</li>
        <li>Make sure your email account is secure.</li>
      </ul>
      
      <div style="background: #f1f1f1; padding: 15px; border-radius: 6px; margin: 20px 0; font-size: 14px; color: #666;">
        <h4 style="margin-top: 0;">📍 Login Attempt Details</h4>
        <p style="margin: 0;"><strong>Time:</strong> ${time}<br>
        <strong>IP Address:</strong> ${ipAddress}</p>
      </div>
      
      <p style="font-size: 14px; color: #666;">If you recognize this activity, you can safely unlock your account using the OTP or link above.</p>
      <p style="font-size: 14px; color: #666;">If you did not attempt to sign in, we strongly recommend resetting your password once access is restored.</p>
      
      <p style="margin-top: 30px;">Stay safe,<br>
      Security Team<br>
      <strong>${companyName}</strong></p>
      
      <p style="font-size: 12px; color: #999; text-align: center; margin-top: 40px;">
        Need help? Contact us anytime: <a href="mailto:${supportEmail}" style="color: #0066cc;">${supportEmail}</a>
      </p>
    </div>
  `;
};
