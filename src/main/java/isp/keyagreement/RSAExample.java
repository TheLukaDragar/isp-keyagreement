package isp.keyagreement;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assignments:
 * - Find out how to manually change the RSA modulus size
 * - Set padding to NoPadding. Encrypt a message and decrypt it. Is the
 * decrypted text the same as the original plaint text? Why?
 */
public class RSAExample {

    public static String hex(byte[] in) {
        return DatatypeConverter.printHexBinary(in);
    }

    public static void main(String[] args) throws Exception {
        // Set RSA cipher specs:
        //  - Set mode to ECB: this is an nonsensical value, but is enforced by the underlying Java API
        //    (it is merely an implementation quirk -- otherwise you'd get an exception)
        //  - Set padding to OAEP (preferred mode); alternatives are (the default) is PKCS1Padding and NoPadding
        final String algorithm = "RSA/ECB/OAEPPadding";
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        final byte[] pt = message.getBytes("UTF-8");

        System.out.println("Message: " + message);
        System.out.println("PT: " + hex(pt));

        // STEP 1: Bob creates his public and private key pair.
        // Alice receives Bob's public key.
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        // STEP 2: Alice creates Cipher object defining cipher algorithm.
        // She then encrypts the clear-text and sends it to Bob.
        final Cipher rsaEnc = Cipher.getInstance(algorithm);
        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        final byte[] ct = rsaEnc.doFinal(pt);

        // STEP 3: Display cipher text in hex. This is what an attacker would see,
        // if she intercepted the message.
        System.out.println("CT: " + hex(ct));

        // STEP 4: Bob decrypts the cipher text using the same algorithm and his private key.
        final Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        final byte[] decryptedText = rsaDec.doFinal(ct);

        // STEP 5: Bob displays the clear text
        System.out.println("PT: " + hex(decryptedText));
        final String message2 = new String(decryptedText, "UTF-8");
        System.out.println("Message: " + message2);
    }
}
