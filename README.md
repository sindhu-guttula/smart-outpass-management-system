# Outpass Management System

A role-based web application that digitizes the campus outpass process. Students apply for outpasses, parents approve them with an OTP, mentors give the final approval, and security verifies exit and return using a QR code or outpass ID.

## Roles

| Role | Purpose |
|------|---------|
| Student | Apply for outpasses, track status, view the QR pass, receive notifications |
| Parent | Verify the OTP, monitor the student's outpasses and campus status |
| Mentor | Review parent-approved requests and approve or reject them |
| Security | Verify passes at the gate and record exit and return |

## Outpass Workflow

1. Student logs in and applies for an outpass.
2. An OTP is sent to the parent's number stored in the database.
3. Student enters the OTP, and the system marks the request as **parent approved**.
4. Mentor reviews the request (parent approval status and reason) and approves or rejects it.
5. Student is notified that they are ready to exit, and a QR pass is generated.
6. Security scans the QR code or searches by outpass ID, then allows **exit** and records it.
7. When the student comes back, security allows **return** and records it.
8. The parent is notified at each key step (OTP, exit, safe return).

## Features

### Login (`index.html`)
- Select a role (Student, Parent, Mentor, Security) and log in with username and password.
- Multiple users can be logged in on different devices at the same time. Each session loads only that user's details.

### Student (`student/`)
| File | Description |
|------|-------------|
| `dashboard.html` | Counts for total, pending, approved and completed requests. Modules: Apply Outpass, My Outpasses, Active Pass, History, Notifications, Logout |
| `apply-outpass.html` | Student details are auto-filled from the logged-in account. The form takes destination, outpass date, expected exit time, return date and reason, and the student must accept a declaration. After submitting, an OTP goes to the parent. The student enters it, and the system verifies it and confirms parent approval |
| `my-outpasses.html` | Shows the status of each outpass, such as waiting for parent approval or waiting for mentor approval |
| `pass.html` | Generates a QR code containing the student's details and approval status (parent approved, mentor approved, and so on), which security scans |
| `notifications.html` | Shows alerts such as "Mentor approved, you are ready to exit" |

### Parent (`parent/`)
| File | Description |
|------|-------------|
| `pdashboard.html` | Student information, pending approvals, currently outside campus, safely returned, total outpasses, plus Outpass Requests and Notifications |
| `outpass-requests.html` | Status of the child's outpasses |
| `pnotifications.html` | Notifications for: **1) OTP, 2) student exited campus, 3) student safely returned** |

### Mentor (`mentor/`)
| File | Description |
|------|-------------|
| `mdashboard.html` | Counts for pending, approved, rejected and total requests. "Review Request" opens parent approval status and reason, with Approve and Reject actions |
| `outpass-requests.html` | Requests that arrived after parent approval |
| `mhistory.html` | Outpass ID and student information for past requests, with an option to view all decisions |

### Security (`security/`)
| File | Description |
|------|-------------|
| `sdashboard.html` | Counts for approved outpasses, currently outside, returned today and awaiting verification. Verification by outpass ID search or QR scan shows the outpass details and lets security allow exit or return. Each action is recorded and the parent is notified |
| `exit-records.html` | Log of when students left the campus |
| `return-records.html` | Log of when students returned to the campus |

## Notifications

| Phase | Channel | Status |
|-------|---------|--------|
| Current semester | Email to students, parents, mentors and security | In scope now |
| Future | SMS to parent mobile numbers (OTP, exit, safe return) | Planned, since SMS gateways are paid |
| Testing | OTP printed in the server terminal | Used until SMS or email OTP is live |

## Project Structure

```
project-root/
├── index.html
├── student/
│   ├── dashboard.html
│   ├── apply-outpass.html
│   ├── my-outpasses.html
│   ├── pass.html
│   └── notifications.html
├── parent/
│   ├── pdashboard.html
│   ├── outpass-requests.html
│   └── pnotifications.html
├── mentor/
│   ├── mdashboard.html
│   ├── outpass-requests.html
│   └── mhistory.html
└── security/
    ├── sdashboard.html
    ├── exit-records.html
    └── return-records.html
```

## Outpass Status Flow

```
Applied -> Waiting for Parent OTP -> Parent Approved -> Waiting for Mentor
        -> Mentor Approved (Ready to Exit) -> Exited -> Returned (Completed)
                         \-> Rejected
```

## Setup and Running

> Fill in the details below to match your stack.

1. Clone the repository.
2. Install dependencies: `<install command>`
3. Configure the database connection and email credentials in `<config / .env file>`.
4. Start the server: `<run command>`
5. Open `index.html` (or the server URL) in a browser.

During testing, watch the terminal where the server runs to read the parent OTP.

## Roadmap

- [x] Role-based login
- [x] Outpass application with parent OTP verification
- [x] Mentor approval workflow
- [x] QR pass generation and security verification
- [x] Exit and return records
- [ ] Email notifications for all roles (this semester)
- [ ] SMS notifications to parents (after the core project is complete)

## Team

Add team member names and roles here.
