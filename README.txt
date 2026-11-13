QR MedCheck — Student Website Prototype
=======================================

WHAT'S INCLUDED
- Browser interface for Dashboard, Patients, Medication Inventory, Camera Station,
  QR Code Center, Staff Accounts, Safety Logs, Subscription Plans, and Prescriptions.
- Fictional sample data and SQLite persistence on the computer running the server.
- QR generation and scanning, patient scheduling with an optional phone number,
  prescription history, and email-and-password sign-in.
- This is a learning prototype. Use fictional data only.

RUN LOCALLY
1. Open a terminal in the qr_medcheck folder.
2. Install the backend dependency: `py -m pip install -r requirements.txt`.
3. Either create the first clinic IT Administrator from the start page, or set the
   seeded fictional Administrator password from the command line:
   `py server.py --set-password alex.admin@example.test`
   Enter and confirm a password with at least 8 characters.
   If the Alex Administrator profile was deleted, restore it and set a new password
   with `py server.py --restore-admin`.
4. Start the application: `py server.py`
5. On the same computer, open `http://localhost:8766/`. First-time signup asks for
   the administrator's full name, clinic/facility name, email, password confirmation,
   optional contact number, subscription tier, and a demo payment-method choice.
   The first-administrator registration saves the account, linked clinic profile,
   selected plan and payment-method choice, bcrypt password hash, and signed-in JWT
   session together in the local database.
   In Local Demo Mode, a checkout signup can also replace the current IT Administrator:
   the previous administrator's password and sessions are revoked, and the new account
   becomes the IT Administrator for the clinic. This replaces the clinic name and plan
   with the values entered in checkout. Otherwise, sign in with the Administrator email
   and password you set above.
6. If no clinic plan has been selected, sign in as the IT Administrator and complete
   the guided checkout. The payment method choices are for demonstration only: no
   payment details are collected and no payment or recurring subscription is processed.
   The plan applies to the clinic and is shared by staff; staff sign-ins do not display
   plan selection. Plans are stored in the local database.

To stop the server, return to its terminal and press Ctrl+C. The database file
`qr_medcheck_demo.sqlite3` is stored alongside the application. Existing records are
preserved; fictional staff and medication examples are added only when those tables
are empty. Startup adds any needed profile fields, password-hash column, session table,
clinic ownership and payment-method fields, JWT signing secret, and shared clinic
subscription setting if missing; it does not drop staff, passwords, sessions, or
prescription records.

DEMO PROFILES, ROLES, AND LIMITS
- Initial fictional profiles include Ylona Leigh (Nurse, Ward 4B), Marcus
  (Pharmacist, Pharmacy), Alex (Administrator, IT Administration), Dr. Jamie Cruz
  (Physician, Medical Department), and Taylor (Head Nurse / Nursing Supervisor,
  Ward 4B).
- Administrators can add, edit, search, and delete staff profiles. Use Set password
  on a staff row before that account can sign in. Reset the Administrator password
  from the local command line with `py server.py --set-password ADMIN_EMAIL`. If Alex
  was deleted and no Administrator remains, run `py server.py --restore-admin` to
  restore Alex (Administrator, IT Administration) and set a new password.
- Clinic registration is handled by `POST /api/auth/register`. It validates the
  `name`, `clinicName`, `email`, `password`, `plan`, and `paymentMethod` fields,
  creates an IT Administrator in the existing `staff_accounts` table, links or updates
  the `clinic_profile` record, bcrypt-hashes the password, and issues a signed JWT both
  in the response and as the HttpOnly session cookie in one database transaction.
  During checkout, the selected Demo Mode tier is saved as active. If an IT Administrator
  already exists, checkout replaces that administrator's sign-in access by clearing
  the old password and sessions, then assigns clinic ownership and the active plan to
  the newly created account. The separate initial signup form can save a preferred tier
  without activating it until the subsequent plan confirmation.
  `POST /api/auth/login` looks up credentials in `staff_accounts`, verifies passwords,
  upgrades older PBKDF2 hashes to bcrypt after a successful login, and returns the
  user profile, clinic name, active plan, and a new JWT. Unknown emails and incorrect
  passwords both return `Invalid email or password.`
  Existing API authorization accepts the session cookie or `Authorization: Bearer`
  JWT and checks the corresponding server-side session so logout and password resets
  revoke tokens. Public IT Administrator takeover is intended only for the local demo:
  no payment is actually processed or verified. Do not expose this registration flow
  to the internet or use it for production accounts. Open the app through `http://localhost:8766/`, not
  from a `file:///` URL, for server-backed registration and sign-in.
- New and reset passwords use bcrypt hashes; existing PBKDF2 passwords are upgraded
  on successful sign-in. The server issues an HttpOnly, SameSite session cookie that
  expires after 12 hours; signing out invalidates it. JWT signing uses a persisted
  local secret unless `QR_MEDCHECK_JWT_SECRET` is configured.
- Nurse, Pharmacist, Administrator, Physician, and Head Nurse / Nursing Supervisor
  have role-specific navigation and prototype API behavior. Optional future roles
  (Inventory Manager, Auditor / Quality Officer, and IT Support) are not enabled.
- Nurse and Head Nurse demo profiles can generate medication unit-dose labels in
  Label Studio. Medication Inventory changes remain limited to the Pharmacist role.
- Starter (₱999/month) allows up to 5 staff, Growth (₱2,499/month) allows up to 15,
  and Enterprise (₱4,999/month) allows up to 50. Only the IT Administrator can choose
  or change the clinic's Demo Mode plan. Once selected, the tier is shared across
  staff accounts and gates app sections and API data for every role. No payment is
  collected and no recurring subscription is purchased. Checkout takeover is a demo
  convenience, not proof of clinic ownership or payment.

IMPORTANT LIMITATIONS
- This is classroom authentication and a simulated subscription gate, not production
  identity, billing, or access security. Checkout payment methods are mock selections;
  no payment is processed. The server uses HTTP, so session cookies
  and data are not encrypted in transit. Do not expose
  this prototype to the internet or use real patient information or production
  passwords.
- Public QR links are intentionally viewable by anyone who scans them and can reveal
  their linked record. Use fictional records only.
- Real deployment requires HTTPS, a production-grade identity and authorization
  system, privacy review, clinical validation, and independent security testing.
- Camera access on phones generally requires HTTPS; QR generation and scanning
  libraries load from a CDN and need internet access.

PRESCRIPTION WORKFLOW
- Sign in as the Physician and open Prescriptions. Select an existing patient and a
  medication from the Medication Inventory dropdown. A Physician can add a new
  medication record from the prescription form; it starts with stock set to 0 and
  does not verify the medication or its clinical safety. Pharmacists remain
  responsible for managing stock.
- Required details, numeric values, and dates are validated. Prescriptions persist
  in SQLite across page refreshes and server restarts.
- New prescriptions start as Draft. The prototype allows Draft to Active or
  Cancelled, and Active to Discontinued. Cancellation and discontinuation require a
  reason. Finalized records remain in prescription history.
- Prescription and audit attribution use the authenticated staff account, but the
  records are still prototype data and are not immutable or independently protected.
- Allergy, route, expiration, stock, and duplicate-order checks can show warnings or
  missing-data notices. These are limited checks, not clinical review,
  drug-interaction checking, or a guarantee of safety. Activation is not a clinical
  safety decision.

QUICK TEST
1. Set Alex's initial password with `py server.py --set-password alex.admin@example.test`,
   start the server, and sign in. Confirm Subscription Plans opens before app features.
   Choose or switch tiers in checkout, create the first clinic IT Administrator account
   (or sign in with the existing IT Administrator), select a payment method, and review
   the account and plan details. Confirm & Activate Account should open the Clinic Admin
   Dashboard; no payment is made.
2. Add a fictional staff profile, set its password, sign out, and sign in with the
   new credentials. Try editing, searching, and deleting staff; test invalid and
   duplicate email addresses.
3. Sign in as the Physician, create an Active order for an existing patient and medication,
   then check the patient directory and refresh to confirm it remains active. Review
   warnings carefully; activation does not confirm clinical safety. Try discontinuing it;
   a reason is required.
4. Sign in separately as Nurse, Pharmacist, and Head Nurse to check their navigation.
   Unauthenticated API calls should return 401; role-restricted API calls should
   return 403.
5. Change the Demo Mode plan and confirm the displayed staff limit changes. Sign out
   and sign in again to verify the plan confirmation gate resets.
6. Try Camera Station with fictional sample records. A QR scan or field match is not
   proof that medication is safe to administer.

OTHER LIMITATIONS
- Audit events are application records, not immutable or independently protected.
- Patient records do not have department/unit or responsible-physician assignments.
- Prescription warnings do not determine clinical appropriateness or guarantee
  medication safety.
- A QR match cannot establish patient condition, package integrity, or authorization
  to administer medication. Follow professional judgment and facility policy.
