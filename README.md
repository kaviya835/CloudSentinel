# CloudSentinel — Cloud Security Monitoring Dashboard

CloudSentinel is a Python Flask-based cybersecurity portfolio project designed to demonstrate security event monitoring, suspicious login detection, honeyfile simulation, and file integrity monitoring for local files and AWS S3 objects.

## Features

- **Security Dashboard:** View recorded security events and high-risk alerts.
- **Login Monitoring:** Simulate repeated failed login attempts and detect suspicious activity.
- **Honeyfile Simulation:** Generate a high-risk alert when a simulated honeyfile is accessed.
- **Local File Integrity Monitoring:** Use SHA-256 hashes to detect file changes.
- **AWS S3 File Integrity Monitoring:** Retrieve an S3 object and compare its hash against a stored baseline.
- **Security Alert History:** Review recorded events with risk scores and severity levels.

## Technology Stack

- Python
- Flask
- SQLite
- Boto3
- Amazon S3
- SHA-256
- HTML and CSS

## Project Structure

```text
CloudSentinel/
├── app.py
├── file_monitor.py
├── s3_file_monitor.py
├── aws_s3_test.py
├── requirements.txt
├── .gitignore
└── README.md
```

Runtime files such as the SQLite database and hash-baseline files are generated locally and should not be committed.

## Local Setup

1. Install Python 3.10 or a compatible version.
2. Clone this repository and open the project directory.
3. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Configure AWS credentials securely using the AWS CLI if you want to test the S3 integration.
5. Update the bucket and object configuration in the project to match your own test environment.
6. Run the dashboard:

   ```bash
   python app.py
   ```

7. Open `http://127.0.0.1:5000` in your browser.

## Security Notes

- Never commit AWS access keys, secret keys, passwords, or other credentials.
- Use least-privilege IAM permissions for AWS testing.
- Keep the Flask development server local; do not expose debug mode publicly.
- This project is a learning and demonstration tool, not a production security monitoring system.
- The current S3 integrity check detects content differences when the monitor runs. It does not independently provide continuous, event-driven monitoring.

## Testing

The following features have been manually tested in the development environment:

- Dashboard loading
- Login failure detection
- Honeyfile simulation
- Local file integrity monitoring
- AWS S3 object integrity status
- Security alert history

## Future Improvements

- Add automated unit tests.
- Improve incident evidence and alert reporting.
- Add S3 event-driven monitoring.
- Improve configuration management and deployment security.

## Author

Developed as a cybersecurity portfolio project to practise Python programming, security event handling, file integrity monitoring, and AWS S3 integration.
