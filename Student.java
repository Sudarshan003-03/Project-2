
import java.sql.*;
import java.util.Scanner;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PlacementManagement {

    static Scanner sc = new Scanner(System.in);

    static final String URL =
        "jdbc:mysql://localhost:3306/placement_db";

    static final String USER = "root";
    static final String PASSWORD = "your_password";

    // DATABASE CONNECTION
    static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(
            URL, USER, PASSWORD
        );
    }

    // GENERATE RANDOM SALT
    static String generateSalt() {

        byte[] salt = new byte[16];

        new SecureRandom().nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    // PASSWORD HASHING USING PBKDF2
    static String hashPassword(
            String password, String salt) throws Exception {

        byte[] saltBytes =
            Base64.getDecoder().decode(salt);

        KeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            saltBytes,
            210000,
            256
        );

        SecretKeyFactory factory =
            SecretKeyFactory.getInstance(
                "PBKDF2WithHmacSHA256"
            );

        byte[] hash =
            factory.generateSecret(spec).getEncoded();

        return Base64.getEncoder()
                     .encodeToString(hash);
    }

    // VERIFY PASSWORD
    static boolean verifyPassword(
            String password,
            String salt,
            String storedHash) throws Exception {

        byte[] newHash = Base64.getDecoder().decode(
            hashPassword(password, salt)
        );

        byte[] oldHash =
            Base64.getDecoder().decode(storedHash);

        return MessageDigest.isEqual(newHash, oldHash);
    }

    // MAIN METHOD
    public static void main(String[] args) {

        while (true) {

            System.out.println("\n================================");
            System.out.println(" STUDENT PLACEMENT MANAGEMENT ");
            System.out.println("================================");

            System.out.println("1. Student Registration");
            System.out.println("2. Student Login");
            System.out.println("3. Exit");

            System.out.print("Enter choice: ");

            int choice = sc.nextInt();
            sc.nextLine();

            try {

                switch (choice) {

                    case 1:
                        registerStudent();
                        break;

                    case 2:
                        loginStudent();
                        break;

                    case 3:
                        System.out.println("Thank you!");
                        return;

                    default:
                        System.out.println("Invalid choice");
                }

            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }

    // STUDENT REGISTRATION
    static void registerStudent() throws Exception {

        System.out.println("\n--- STUDENT REGISTRATION ---");

        System.out.print("Enter name: ");
        String name = sc.nextLine();

        System.out.print("Enter email: ");
        String email = sc.nextLine();

        System.out.print("Enter password: ");
        String password = sc.nextLine();

        System.out.print("Enter CGPA: ");
        double cgpa = sc.nextDouble();

        System.out.print("Enter backlogs: ");
        int backlogs = sc.nextInt();
        sc.nextLine();

        if (name.isBlank() || !email.matches(
                "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$") ||
                password.length() < 8 ||
                cgpa < 0 || cgpa > 10 ||
                backlogs < 0) {

            System.out.println("Invalid input details");
            return;
        }

        String salt = generateSalt();

        String hash = hashPassword(password, salt);

        String sql = """
            INSERT INTO students
            (name, email, password_hash, salt, cgpa, backlogs)
            VALUES (?, ?, ?, ?, ?, ?)
            """;

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, name);
            ps.setString(2, email);
            ps.setString(3, hash);
            ps.setString(4, salt);
            ps.setDouble(5, cgpa);
            ps.setInt(6, backlogs);

            ps.executeUpdate();

            System.out.println("Registration successful!");

        } catch (SQLIntegrityConstraintViolationException e) {
            System.out.println("Email already registered!");
        }
    }

    // STUDENT LOGIN
    static void loginStudent() throws Exception {

        System.out.println("\n--- STUDENT LOGIN ---");

        System.out.print("Enter email: ");
        String email = sc.nextLine();

        System.out.print("Enter password: ");
        String password = sc.nextLine();

        String sql =
            "SELECT * FROM students WHERE email = ?";

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, email);

            try (ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {

                    String salt = rs.getString("salt");

                    String storedHash =
                        rs.getString("password_hash");

                    if (verifyPassword(
                            password, salt, storedHash)) {

                        int studentId =
                            rs.getInt("student_id");

                        System.out.println(
                            "\nWelcome " + rs.getString("name")
                        );

                        studentMenu(studentId);

                    } else {

                        System.out.println("Invalid password");
                    }

                } else {

                    System.out.println("Student not found");
                }
            }
        }
    }

    // STUDENT DASHBOARD
    static void studentMenu(int studentId) throws Exception {

        while (true) {

            System.out.println("\n--- STUDENT DASHBOARD ---");

            System.out.println("1. View Eligible Jobs");
            System.out.println("2. Apply for Job");
            System.out.println("3. Track Applications");
            System.out.println("4. Logout");

            System.out.print("Enter choice: ");

            int choice = sc.nextInt();
            sc.nextLine();

            switch (choice) {

                case 1:
                    viewEligibleJobs(studentId);
                    break;

                case 2:
                    applyForJob(studentId);
                    break;

                case 3:
                    trackApplications(studentId);
                    break;

                case 4:
                    return;

                default:
                    System.out.println("Invalid choice");
            }
        }
    }

    // VIEW ELIGIBLE JOBS
    static void viewEligibleJobs(int studentId)
            throws Exception {

        String sql = """
            SELECT j.job_id, c.company_name,
                   j.job_role, j.min_cgpa
            FROM students s
            JOIN jobs j
              ON s.cgpa >= j.min_cgpa
             AND s.backlogs <= j.max_backlogs
            JOIN companies c
              ON j.company_id = c.company_id
            WHERE s.student_id = ?
            """;

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setInt(1, studentId);

            try (ResultSet rs = ps.executeQuery()) {

                System.out.println("\n--- ELIGIBLE JOBS ---");

                boolean found = false;

                while (rs.next()) {

                    found = true;

                    System.out.println(
                        "\nJob ID: " + rs.getInt("job_id")
                    );

                    System.out.println(
                        "Company: " + rs.getString("company_name")
                    );

                    System.out.println(
                        "Role: " + rs.getString("job_role")
                    );

                    System.out.println(
                        "Minimum CGPA: " + rs.getDouble("min_cgpa")
                    );
                }

                if (!found) {
                    System.out.println("No eligible jobs found");
                }
            }
        }
    }

    // APPLY FOR JOB
    static void applyForJob(int studentId)
            throws Exception {

        System.out.print("Enter Job ID: ");

        int jobId = sc.nextInt();
        sc.nextLine();

        String sql = """
            INSERT INTO applications (student_id, job_id)
            SELECT s.student_id, j.job_id
            FROM students s
            JOIN jobs j
              ON s.cgpa >= j.min_cgpa
             AND s.backlogs <= j.max_backlogs
            WHERE s.student_id = ?
              AND j.job_id = ?
            """;

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setInt(1, studentId);
            ps.setInt(2, jobId);

            int rows = ps.executeUpdate();

            if (rows > 0) {

                System.out.println(
                    "Application submitted successfully!"
                );

            } else {

                System.out.println(
                    "Not eligible or invalid Job ID"
                );
            }

        } catch (SQLIntegrityConstraintViolationException e) {

            System.out.println(
                "You have already applied for this job"
            );
        }
    }

    // TRACK APPLICATIONS
    static void trackApplications(int studentId)
            throws Exception {

        String sql = """
            SELECT c.company_name, j.job_role,
                   a.status, a.applied_at
            FROM applications a
            JOIN jobs j
              ON a.job_id = j.job_id
            JOIN companies c
              ON j.company_id = c.company_id
            WHERE a.student_id = ?
            ORDER BY a.applied_at DESC
            """;

        try (Connection con = getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setInt(1, studentId);

            try (ResultSet rs = ps.executeQuery()) {

                System.out.println("\n--- APPLICATION HISTORY ---");

                boolean found = false;

                while (rs.next()) {

                    found = true;

                    System.out.println(
                        "\nCompany: " + rs.getString("company_name")
                    );

                    System.out.println(
                        "Role: " + rs.getString("job_role")
                    );

                    System.out.println(
                        "Status: " + rs.getString("status")
                    );

                    System.out.println(
                        "Applied At: " + rs.getTimestamp("applied_at")
                    );
                }

                if (!found) {
                    System.out.println("No applications found");
                }
            }
        }
    }
}
