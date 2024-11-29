package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.nio.charset.StandardCharsets;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create key pairs for both agents
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        final KeyPair aliceKey = kpg.generateKeyPair();
        final KeyPair bobKey = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // Send 10 signed messages
                for (int i = 0; i < 10; i++) {
                    // Create and sign message
                    String message = String.format("Message %d from Alice", i);
                    Signature signer = Signature.getInstance("SHA256withECDSA");
                    signer.initSign(aliceKey.getPrivate());
                    signer.update(message.getBytes(StandardCharsets.UTF_8));
                    byte[] signature = signer.sign();

                    // Send message and signature
                    send("bob", message.getBytes(StandardCharsets.UTF_8));
                    send("bob", signature);

                    // Receive and verify Bob's response
                    byte[] receivedMsg = receive("bob");
                    byte[] receivedSig = receive("bob");
                    
                    Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(bobKey.getPublic());
                    verifier.update(receivedMsg);
                    
                    print("Message from Bob: %s (signature valid: %b)", 
                          new String(receivedMsg), 
                          verifier.verify(receivedSig));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive and respond to 10 messages
                for (int i = 0; i < 10; i++) {
                    // Receive and verify Alice's message
                    byte[] receivedMsg = receive("alice");
                    byte[] receivedSig = receive("alice");
                    
                    Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(aliceKey.getPublic());
                    verifier.update(receivedMsg);
                    
                    print("Message from Alice: %s (signature valid: %b)", 
                          new String(receivedMsg), 
                          verifier.verify(receivedSig));

                    // Send response
                    String response = String.format("Response %d from Bob", i);
                    Signature signer = Signature.getInstance("SHA256withECDSA");
                    signer.initSign(bobKey.getPrivate());
                    signer.update(response.getBytes(StandardCharsets.UTF_8));
                    byte[] signature = signer.sign();

                    send("alice", response.getBytes(StandardCharsets.UTF_8));
                    send("alice", signature);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}