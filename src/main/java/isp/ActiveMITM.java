package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class ActiveMITM {
    public static void main(String[] args) throws Exception {
        // David and FMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "prf.denis@fri.si\n" +
                        "david@fri.si\n" +
                        "Some ideas for the exam\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));
                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                print(" IN: %s", hex(ct));

                // We know the original recipient: "prf.denis@fri.si"
                // We want to change it to:      "isp@gmail.com"
                byte[] originalText = "prf.denis@fri.si".getBytes(StandardCharsets.UTF_8);
                byte[] targetText = "isp@gmail.com".getBytes(StandardCharsets.UTF_8);
                
                // Create XOR mask to transform original text to target text
                byte[] mask = new byte[originalText.length];
                for (int i = 0; i < originalText.length; i++) {
                    if (i < targetText.length) {
                        // XOR: original ⊕ target = mask
                        mask[i] = (byte) (originalText[i] ^ targetText[i]);
                    } else {
                        // For any remaining bytes, XOR with original to get null bytes
                        mask[i] = (byte) (originalText[i] ^ 0);
                    }
                }
                
                // Apply the mask to the ciphertext
                byte[] modifiedCt = ct.clone();
                for (int i = 0; i < mask.length; i++) {
                    modifiedCt[i] ^= mask[i];
                }

                print("OUT: %s", hex(modifiedCt));
                send("server", modifiedCt);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");
        env.start();
    }
}
