package org.whispersystems.libsignal;

import junit.framework.TestCase;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.AliceSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.BobSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.RatchetingSession;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.util.guava.Optional;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SessionCipherStreamTest extends TestCase {
    private SessionCipher aliceCipher;
    private SessionCipher bobCipher;

    private void initializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState) throws InvalidKeyException {
        ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();

        IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                aliceIdentityKeyPair.getPrivateKey());
        ECKeyPair aliceBaseKey = Curve.generateKeyPair();
        ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

        ECKeyPair alicePreKey = aliceBaseKey;

        ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                bobIdentityKeyPair.getPrivateKey());
        ECKeyPair bobBaseKey = Curve.generateKeyPair();
        ECKeyPair bobEphemeralKey = bobBaseKey;

        ECKeyPair bobPreKey = Curve.generateKeyPair();

        AliceSignalProtocolParameters aliceParameters =
                AliceSignalProtocolParameters.newBuilder().setOurBaseKey(aliceBaseKey)
                        .setOurIdentityKey(aliceIdentityKey).setTheirOneTimePreKey(Optional.absent())
                        .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                        .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                        .setTheirIdentityKey(bobIdentityKey.getPublicKey()).create();

        BobSignalProtocolParameters bobParameters =
                BobSignalProtocolParameters.newBuilder().setOurRatchetKey(bobEphemeralKey)
                        .setOurSignedPreKey(bobBaseKey).setOurOneTimePreKey(Optional.absent())
                        .setOurIdentityKey(bobIdentityKey).setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                        .setTheirBaseKey(aliceBaseKey.getPublicKey()).create();

        RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
        RatchetingSession.initializeSession(bobSessionState, bobParameters);
    }

    public void setUp() throws InvalidKeyException {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
        SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

        aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
        bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));
    }

    /**
     * Encrypts with StreamedProcess
     * Decrypts with Array
     */
    public void test1ArrayEncryptArrayDecrypt() throws Exception {
        String message = "Hello, World!".repeat(9999);
        SignalMessage signalm = (SignalMessage) aliceCipher.encrypt(message.getBytes());
        byte[] plaintext = bobCipher.decrypt(signalm);
        String decrypted = new String(plaintext, StandardCharsets.UTF_8);
        assertEquals(message, decrypted);
    }

    /**
     * Encrypts with StreamedProcess
     * Decrypts with Array
     */
    public void test2StreamingEncryptStreamingDecrypt() throws Exception {
        var streamSizes = List.of(SessionCipher.STREAM_READ_SIZE, 17, 31, 1000);
        for (int streamSize : streamSizes) {
            String message = "Hello, World!".repeat(100);
            ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
            aliceCipher.encrypt(new ByteArrayInputStream(message.getBytes()), cipherText);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            SessionCipher.STREAM_READ_SIZE = streamSize;
            bobCipher.decrypt(new ByteArrayInputStream(cipherText.toByteArray()), outputStream);
            String decrypted = outputStream.toString(StandardCharsets.UTF_8);
            assertEquals(message, decrypted);
        }
        SessionCipher.STREAM_READ_SIZE = streamSizes.get(0);
    }
}
