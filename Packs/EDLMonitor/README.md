## EDL logger

-You can use the playbook (or a cloned copy) with a job to check the EDL on a schedule, or you can use the integration commands in your own playbooks as needed
-While the EDL contents are timestamped and attached in zip files, due to the nature of the files, zipping will likely not save much space
This is only tested with Gmail using smtp.gmail.com as the server, and you will need to enable 2FA for your google account and create an app password as the regular credentials will no longer work due to new Google security settings.  See https://support.google.com/accounts/answer/185833?hl=en&authuser=2 for details
