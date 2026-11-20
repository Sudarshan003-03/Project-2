
package placement;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

public class PasswordUtil {

    public static String generateSalt() {

        byte[] salt = new byte[16];

        new SecureRandom().nextBytes(salt);

        return Base64.getEncoder()
                     .encodeToString(salt);
    }

    public static String hashPassword(
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

        byte[] hash = factory
            .generateSecret(spec)
            .getEncoded();

        return Base64.getEncoder()
                      .encodeToString(hash);
    }

    public static boolean verifyPassword(
            String password,
            String salt,
            String storedHash) throws Exception {

        String newHash =
            hashPassword(password, salt);

        return java.security.MessageDigest
            .isEqual(
                Base64.getDecoder().decode(newHash),
                Base64.getDecoder().decode(storedHash)
            );
    }
}
