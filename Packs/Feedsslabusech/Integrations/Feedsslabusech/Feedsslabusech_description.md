sslipblacklist.csv:  
The SSL IP Blacklist contains all hosts (IP addresses) that SSLBL has
seen in the past 30 days being associated with a malicious SSL certificate.

sslipblacklist_aggressive.csv:  
The SSL IP Blacklist contains all hosts (IP addresses) that SSLBL has
seen in the past being associated with a malicious SSL certificate. Warning - High FP Rate!

sslblacklist.csv:
The SSL IP Blacklist contains SHA1 Fingerprint of all SSL certificates blacklisted on SSLBL. 
The SSL Certificate Blacklist (CSV) gets generated every 5 minutes. Please do not fetch it more often than every 5 minutes.

#### Create an Auth Key for abuse.ch
> Note: If you already have a profile, you can skip steps 1 and 2.

1. Sign up for an abuse.ch account. You can do this easily by using an existing account that you may already have on X, LinkedIn, Google or Github. Just log in with the authentication provider of your choice here: https://auth.abuse.ch/
  
2. Once you are authenticated on abuse.ch, ensure that you connect at least one additional authentication provider. This will ensure that you have access to abuse.ch platforms, even if one of the authentication providers you use shuts down (yes, it happened with Twitter!)

3. Ensure that you hit the "Save profile" button. In the "Optional" section, you can now generate an "Auth-Key". This is your personal Auth-Key that you can now use in the integration.