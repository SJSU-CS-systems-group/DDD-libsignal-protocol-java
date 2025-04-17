/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.ChainKey;
import org.whispersystems.libsignal.ratchet.MessageKeys;
import org.whispersystems.libsignal.ratchet.RootKey;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.PreKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.libsignal.state.SignedPreKeyStore;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.guava.Optional;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.Math.max;
import static org.whispersystems.libsignal.state.SessionState.UnacknowledgedPreKeyMessageItems;

/**
 * The main entry point for Signal Protocol encrypt/decrypt operations.
 *
 * Once a session has been established with {@link SessionBuilder},
 * this class can be used for all encrypt/decrypt operations within
 * that session.
 *
 * @author Moxie Marlinspike
 */
public class SessionCipher {

  public static final Object SESSION_LOCK = new Object();

  private final SessionStore          sessionStore;
  private final IdentityKeyStore      identityKeyStore;
  private final SessionBuilder        sessionBuilder;
  private final PreKeyStore           preKeyStore;
  private final SignalProtocolAddress remoteAddress;

  /**
   * Construct a SessionCipher for encrypt/decrypt operations on a session.
   * In order to use SessionCipher, a session must have already been created
   * and stored using {@link SessionBuilder}.
   *
   * @param  sessionStore The {@link SessionStore} that contains a session for this recipient.
   * @param  remoteAddress  The remote address that messages will be encrypted to or decrypted from.
   */
  public SessionCipher(SessionStore sessionStore, PreKeyStore preKeyStore,
                       SignedPreKeyStore signedPreKeyStore, IdentityKeyStore identityKeyStore,
                       SignalProtocolAddress remoteAddress)
  {
    this.sessionStore     = sessionStore;
    this.preKeyStore      = preKeyStore;
    this.identityKeyStore = identityKeyStore;
    this.remoteAddress    = remoteAddress;
    this.sessionBuilder   = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                                               identityKeyStore, remoteAddress);
  }

  public SessionCipher(SignalProtocolStore store, SignalProtocolAddress remoteAddress) {
    this(store, store, store, store, remoteAddress);
  }

  /**
   * Encrypt a message.
   *
   * @param  paddedMessage The plaintext message bytes, optionally padded to a constant multiple.
   * @return A ciphertext message encrypted to the recipient+device tuple.
   */
  public CiphertextMessage encrypt(byte[] paddedMessage) throws UntrustedIdentityException {
    synchronized (SESSION_LOCK) {
      SessionRecord sessionRecord   = sessionStore.loadSession(remoteAddress);
      SessionState  sessionState    = sessionRecord.getSessionState();
      ChainKey      chainKey        = sessionState.getSenderChainKey();
      MessageKeys   messageKeys     = chainKey.getMessageKeys();
      ECPublicKey   senderEphemeral = sessionState.getSenderRatchetKey();
      int           previousCounter = sessionState.getPreviousCounter();
      int           sessionVersion  = sessionState.getSessionVersion();

      byte[]            ciphertextBody    = getCiphertext(messageKeys, paddedMessage);
      CiphertextMessage ciphertextMessage = new SignalMessage(sessionVersion, messageKeys.getMacKey(),
                                                              senderEphemeral, chainKey.getIndex(),
                                                              previousCounter, ciphertextBody,
                                                              sessionState.getLocalIdentityKey(),
                                                              sessionState.getRemoteIdentityKey());

      if (sessionState.hasUnacknowledgedPreKeyMessage()) {
        UnacknowledgedPreKeyMessageItems items = sessionState.getUnacknowledgedPreKeyMessageItems();
        int localRegistrationId = sessionState.getLocalRegistrationId();

        ciphertextMessage = new PreKeySignalMessage(sessionVersion, localRegistrationId, items.getPreKeyId(),
                                                    items.getSignedPreKeyId(), items.getBaseKey(),
                                                    sessionState.getLocalIdentityKey(),
                                                    (SignalMessage) ciphertextMessage);
      }

      sessionState.setSenderChainKey(chainKey.getNextChainKey());

      if (!identityKeyStore.isTrustedIdentity(remoteAddress, sessionState.getRemoteIdentityKey(), IdentityKeyStore.Direction.SENDING)) {
        throw new UntrustedIdentityException(remoteAddress.getName(), sessionState.getRemoteIdentityKey());
      }

      identityKeyStore.saveIdentity(remoteAddress, sessionState.getRemoteIdentityKey());
      sessionStore.storeSession(remoteAddress, sessionRecord);
      return ciphertextMessage;
    }
  }

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *                                is no longer supported.
   * @throws InvalidKeyIdException when there is no local {@link org.whispersystems.libsignal.state.PreKeyRecord}
   *                               that corresponds to the PreKey ID in the message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  public byte[] decrypt(PreKeySignalMessage ciphertext)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException,
             InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
  {
    return decrypt(ciphertext, new NullDecryptionCallback());
  }

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link PreKeySignalMessage} to decrypt.
   * @param  callback   A callback that is triggered after decryption is complete,
   *                    but before the updated session state has been committed to the session
   *                    DB.  This allows some implementations to store the committed plaintext
   *                    to a DB first, in case they are concerned with a crash happening between
   *                    the time the session state is updated but before they're able to store
   *                    the plaintext to disk.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *                                is no longer supported.
   * @throws InvalidKeyIdException when there is no local {@link org.whispersystems.libsignal.state.PreKeyRecord}
   *                               that corresponds to the PreKey ID in the message.
   * @throws InvalidKeyException when the message is formatted incorrectly.
   * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
   */
  public byte[] decrypt(PreKeySignalMessage ciphertext, DecryptionCallback callback)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException,
             InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException
  {
    synchronized (SESSION_LOCK) {
      SessionRecord     sessionRecord    = sessionStore.loadSession(remoteAddress);
      Optional<Integer> unsignedPreKeyId = sessionBuilder.process(sessionRecord, ciphertext);
      byte[]            plaintext        = decrypt(sessionRecord, ciphertext.getWhisperMessage());

      callback.handlePlaintext(plaintext);

      sessionStore.storeSession(remoteAddress, sessionRecord);

      if (unsignedPreKeyId.isPresent()) {
        preKeyStore.removePreKey(unsignedPreKeyId.get());
      }

      return plaintext;
    }
  }

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link SignalMessage} to decrypt.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *                                is no longer supported.
   * @throws NoSessionException if there is no established session for this contact.
   */
  public byte[] decrypt(SignalMessage ciphertext)
      throws InvalidMessageException, DuplicateMessageException, LegacyMessageException,
      NoSessionException, UntrustedIdentityException
  {
    return decrypt(ciphertext, new NullDecryptionCallback());
  }

  /**
   * Decrypt a message.
   *
   * @param  ciphertext The {@link SignalMessage} to decrypt.
   * @param  callback   A callback that is triggered after decryption is complete,
   *                    but before the updated session state has been committed to the session
   *                    DB.  This allows some implementations to store the committed plaintext
   *                    to a DB first, in case they are concerned with a crash happening between
   *                    the time the session state is updated but before they're able to store
   *                    the plaintext to disk.
   *
   * @return The plaintext.
   * @throws InvalidMessageException if the input is not valid ciphertext.
   * @throws DuplicateMessageException if the input is a message that has already been received.
   * @throws LegacyMessageException if the input is a message formatted by a protocol version that
   *                                is no longer supported.
   * @throws NoSessionException if there is no established session for this contact.
   */
  public byte[] decrypt(SignalMessage ciphertext, DecryptionCallback callback)
      throws InvalidMessageException, DuplicateMessageException, LegacyMessageException,
             NoSessionException, UntrustedIdentityException
  {
    synchronized (SESSION_LOCK) {

      if (!sessionStore.containsSession(remoteAddress)) {
        throw new NoSessionException("No session for: " + remoteAddress);
      }

      SessionRecord sessionRecord = sessionStore.loadSession(remoteAddress);
      byte[]        plaintext     = decrypt(sessionRecord, ciphertext);

      if (!identityKeyStore.isTrustedIdentity(remoteAddress, sessionRecord.getSessionState().getRemoteIdentityKey(), IdentityKeyStore.Direction.RECEIVING)) {
        throw new UntrustedIdentityException(remoteAddress.getName(), sessionRecord.getSessionState().getRemoteIdentityKey());
      }

      identityKeyStore.saveIdentity(remoteAddress, sessionRecord.getSessionState().getRemoteIdentityKey());

      callback.handlePlaintext(plaintext);

      sessionStore.storeSession(remoteAddress, sessionRecord);

      return plaintext;
    }
  }

  private byte[] decrypt(SessionRecord sessionRecord, SignalMessage ciphertext)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException
  {
    synchronized (SESSION_LOCK) {
      Iterator<SessionState> previousStates = sessionRecord.getPreviousSessionStates().iterator();
      List<Exception>        exceptions     = new LinkedList<>();

      try {
        SessionState sessionState = new SessionState(sessionRecord.getSessionState());
        byte[]       plaintext    = decrypt(sessionState, ciphertext);

        sessionRecord.setState(sessionState);
        return plaintext;
      } catch (InvalidMessageException e) {
        exceptions.add(e);
      }

      while (previousStates.hasNext()) {
        try {
          SessionState promotedState = new SessionState(previousStates.next());
          byte[]       plaintext     = decrypt(promotedState, ciphertext);

          previousStates.remove();
          sessionRecord.promoteState(promotedState);

          return plaintext;
        } catch (InvalidMessageException e) {
          exceptions.add(e);
        }
      }

      throw new InvalidMessageException("No valid sessions.", exceptions);
    }
  }

  private byte[] decrypt(SessionState sessionState, SignalMessage ciphertextMessage)
      throws InvalidMessageException, DuplicateMessageException, LegacyMessageException
  {
    if (!sessionState.hasSenderChain()) {
      throw new InvalidMessageException("Uninitialized session!");
    }

    if (ciphertextMessage.getMessageVersion() != sessionState.getSessionVersion()) {
      throw new InvalidMessageException(String.format("Message version %d, but session version %d",
                                                      ciphertextMessage.getMessageVersion(),
                                                      sessionState.getSessionVersion()));
    }

    ECPublicKey    theirEphemeral    = ciphertextMessage.getSenderRatchetKey();
    int            counter           = ciphertextMessage.getCounter();
    ChainKey       chainKey          = getOrCreateChainKey(sessionState, theirEphemeral);
    MessageKeys    messageKeys       = getOrCreateMessageKeys(sessionState, theirEphemeral,
                                                              chainKey, counter);

    ciphertextMessage.verifyMac(sessionState.getRemoteIdentityKey(),
                                sessionState.getLocalIdentityKey(),
                                messageKeys.getMacKey());

    byte[] plaintext = getPlaintext(messageKeys, ciphertextMessage.getBody());

    sessionState.clearUnacknowledgedPreKeyMessage();

    return plaintext;
  }

  public int getRemoteRegistrationId() {
    synchronized (SESSION_LOCK) {
      SessionRecord record = sessionStore.loadSession(remoteAddress);
      return record.getSessionState().getRemoteRegistrationId();
    }
  }

  public int getSessionVersion() {
    synchronized (SESSION_LOCK) {
      if (!sessionStore.containsSession(remoteAddress)) {
        throw new IllegalStateException(String.format("No session for (%s)!", remoteAddress));
      }

      SessionRecord record = sessionStore.loadSession(remoteAddress);
      return record.getSessionState().getSessionVersion();
    }
  }

  private ChainKey getOrCreateChainKey(SessionState sessionState, ECPublicKey theirEphemeral)
      throws InvalidMessageException
  {
    try {
      if (sessionState.hasReceiverChain(theirEphemeral)) {
        return sessionState.getReceiverChainKey(theirEphemeral);
      } else {
        RootKey                 rootKey         = sessionState.getRootKey();
        ECKeyPair               ourEphemeral    = sessionState.getSenderRatchetKeyPair();
        Pair<RootKey, ChainKey> receiverChain   = rootKey.createChain(theirEphemeral, ourEphemeral);
        ECKeyPair               ourNewEphemeral = Curve.generateKeyPair();
        Pair<RootKey, ChainKey> senderChain     = receiverChain.first().createChain(theirEphemeral, ourNewEphemeral);

        sessionState.setRootKey(senderChain.first());
        sessionState.addReceiverChain(theirEphemeral, receiverChain.second());
        sessionState.setPreviousCounter(max(sessionState.getSenderChainKey().getIndex()-1, 0));
        sessionState.setSenderChain(ourNewEphemeral, senderChain.second());

        return receiverChain.second();
      }
    } catch (InvalidKeyException e) {
      throw new InvalidMessageException(e);
    }
  }

  private MessageKeys getOrCreateMessageKeys(SessionState sessionState,
                                             ECPublicKey theirEphemeral,
                                             ChainKey chainKey, int counter)
      throws InvalidMessageException, DuplicateMessageException
  {
    if (chainKey.getIndex() > counter) {
      if (sessionState.hasMessageKeys(theirEphemeral, counter)) {
        return sessionState.removeMessageKeys(theirEphemeral, counter);
      } else {
        throw new DuplicateMessageException("Received message with old counter: " +
                                                chainKey.getIndex() + " , " + counter);
      }
    }

    if (counter - chainKey.getIndex() > 2000) {
      throw new InvalidMessageException("Over 2000 messages into the future!");
    }

    while (chainKey.getIndex() < counter) {
      MessageKeys messageKeys = chainKey.getMessageKeys();
      sessionState.setMessageKeys(theirEphemeral, messageKeys);
      chainKey = chainKey.getNextChainKey();
    }

    sessionState.setReceiverChainKey(theirEphemeral, chainKey.getNextChainKey());
    return chainKey.getMessageKeys();
  }

  private byte[] getCiphertext(MessageKeys messageKeys, byte[] plaintext) {
    try {
      Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
      return cipher.doFinal(plaintext);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] getPlaintext(MessageKeys messageKeys, byte[] cipherText)
      throws InvalidMessageException
  {
    try {
      Cipher cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
      return cipher.doFinal(cipherText);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidMessageException(e);
    }
  }

  private Cipher getCipher(int mode, SecretKeySpec key, IvParameterSpec iv) {
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(mode, key, iv);
      return cipher;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
             InvalidAlgorithmParameterException e)
    {
      throw new AssertionError(e);
    }
  }

  private static class NullDecryptionCallback implements DecryptionCallback {
    @Override
    public void handlePlaintext(byte[] plaintext) {}
  }

  // ADDED FOR DDD

  public static int STREAM_READ_SIZE = 8 * 1024;

  /**
   * Encrypt a message using streams
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream) throws IOException {
    synchronized (SESSION_LOCK) {
      SessionRecord sessionRecord = sessionStore.loadSession(remoteAddress);
      SessionState sessionState = sessionRecord.getSessionState();
      ChainKey chainKey = sessionState.getSenderChainKey();
      MessageKeys messageKeys = chainKey.getMessageKeys();
      ECPublicKey senderEphemeral = sessionState.getSenderRatchetKey();
      int previousCounter = sessionState.getPreviousCounter();
      int sessionVersion = sessionState.getSessionVersion();

      //First Byte into Output
      outputStream.write(sessionVersion);

      //Next Byte Shows Length of PK
      outputStream.write(senderEphemeral.serialize().length);
      outputStream.write(senderEphemeral.serialize());

      //Counter
      outputStream.write(ByteUtil.intToByteArray(messageKeys.getCounter()));

      //PrevCounter
      outputStream.write(ByteUtil.intToByteArray(previousCounter));

      // since we are encrypting, we are the receiver and remote is the sender
      getCiphertext(sessionVersion, sessionState.getLocalIdentityKey().getPublicKey(),
              sessionState.getRemoteIdentityKey().getPublicKey(), messageKeys, inputStream, outputStream);

      // Update session state
      sessionState.setSenderChainKey(chainKey.getNextChainKey());
      sessionStore.storeSession(remoteAddress, sessionRecord);
    }
  }

  public void decrypt(InputStream inputStream, OutputStream outputStream) throws InvalidMessageException,
          DuplicateMessageException, NoSessionException, IOException, InvalidKeyException {
    synchronized (SESSION_LOCK) {
      if (!sessionStore.containsSession(remoteAddress)) {
        throw new NoSessionException("No session for: " + remoteAddress);
      }

      SessionRecord sessionRecord = sessionStore.loadSession(remoteAddress);
      Iterator<SessionState> previousStates = sessionRecord.getPreviousSessionStates().iterator();
      List<Exception> exceptions = new LinkedList<>();

      // Load session state
      SessionState sessionState = previousStates.hasNext() ? new SessionState(previousStates.next())
              : new SessionState(sessionRecord.getSessionState());
      if (!sessionState.hasSenderChain()) {
        throw new InvalidMessageException("Uninitialized session!");
      }

      byte[] versionArr = new byte[1];
      if(inputStream.read(versionArr) == -1){
        throw new InvalidMessageException("No Version Found");
      }
      int version = versionArr[0];
      if(version < 3){
        throw new InvalidMessageException("Version is less than 3");
      }
      byte[] ratchetKeyInfo = new byte[1];
      if(inputStream.read(ratchetKeyInfo) == -1){
        throw new InvalidMessageException("No Ratchet KeyInfo");
      }
      byte[] ratchetKey = new byte[ratchetKeyInfo[0]];
      if(inputStream.read(ratchetKey) != ratchetKeyInfo[0]){
        throw new InvalidMessageException("Not enough Ratchet Key Bytes Found:"
                + ratchetKey.length +" Expected:" + ratchetKeyInfo[0]);
      }

      //Counter
      byte[] counterArr = new byte[4];
      inputStream.read(counterArr);
      int counter = ByteUtil.byteArrayToInt(counterArr);

      //PrevCounter
      byte[] prevCounterArr = new byte[4];
      inputStream.read(prevCounterArr);
      int prevCounter = ByteUtil.byteArrayToInt(counterArr);

      ECPublicKey theirEphemeral = Curve.decodePoint(ratchetKey,0);

      ChainKey chainKey = getOrCreateChainKey(sessionState, theirEphemeral);
      MessageKeys messageKeys = getOrCreateMessageKeys(sessionState, theirEphemeral, chainKey, counter);

      // since we are decrypting, we are the receiver and remote is the sender
      getPlaintext(version, sessionState.getRemoteIdentityKey().getPublicKey(),
              sessionState.getLocalIdentityKey().getPublicKey(),
              messageKeys ,inputStream, outputStream);
      // Clear any unacknowledged PreKey messages
      sessionState.clearUnacknowledgedPreKeyMessage();

      // Promote or store the session state
      if (previousStates.hasNext()) {
        previousStates.remove();
        sessionRecord.promoteState(sessionState);
      } else {
        sessionRecord.setState(sessionState);
      }
      sessionStore.storeSession(remoteAddress, sessionRecord);
    }
  }


  private void getCiphertext(int version, ECPublicKey senderIdentityKey, ECPublicKey receiverIdentityKey,
                             MessageKeys messageKeys, InputStream plaintext, OutputStream cipherText) throws IOException {
    try {
      Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(messageKeys.getMacKey());
      mac.update(senderIdentityKey.serialize());
      mac.update(receiverIdentityKey.serialize());

      byte[] bytes = new byte[64 * 1024];
      int rc;
      while ((rc = plaintext.read(bytes)) > 0) {
        byte[] cipherBytes = cipher.update(bytes, 0, rc);
        cipherText.write(cipherBytes);
        mac.update(cipherBytes);
      }
      byte[] cipherBytes = cipher.doFinal();
      cipherText.write(cipherBytes);
      mac.update(cipherBytes);
      // 8 bytes of MAC are expected at the end
      byte[] calculatedMac = ByteUtil.trim(mac.doFinal(), 8);
      cipherText.write(calculatedMac);
    } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException |
             java.security.InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  private void getPlaintext(int version, ECPublicKey senderIdentityKey, ECPublicKey receiverIdentityKey,
                              MessageKeys messageKeys, InputStream inputStream,
                              OutputStream outputStream) throws InvalidMessageException, IOException {
    Cipher cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
    CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,cipher);

    Mac mac;
    try {
      mac = Mac.getInstance("HmacSHA256");
      mac.init(messageKeys.getMacKey());
    } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
      throw new AssertionError(e);
    }

    mac.update(senderIdentityKey.serialize());
    mac.update(receiverIdentityKey.serialize());

    byte[] buffer = new byte[STREAM_READ_SIZE];  // ReadSize was modified during testing
    int TRAILING_SIZE = 8;
    byte[] trailingBuffer = new byte[TRAILING_SIZE]; // To store the last 32 bytes
    int trailingCount = 0; //How full our trailingBuffer is

    int readCount;
    while ((readCount = inputStream.read(buffer)) > 0) {
      if (readCount > TRAILING_SIZE) {
        cipherOutputStream.write(trailingBuffer, 0 , trailingCount);
        mac.update(trailingBuffer, 0, trailingCount);
        int bytesToWriteToOutput = readCount - TRAILING_SIZE;
        cipherOutputStream.write(buffer, 0, bytesToWriteToOutput);
        mac.update(buffer, 0, bytesToWriteToOutput);
        System.arraycopy(buffer, bytesToWriteToOutput, trailingBuffer,0, TRAILING_SIZE);
        trailingCount = TRAILING_SIZE;
      } else {
        int bytesToWriteIntoOutput = max(0,(readCount + trailingCount) - TRAILING_SIZE); // All data - 32, write to outPutStream
        if(bytesToWriteIntoOutput > 0) { //Avoid SystemCopyIssues
          cipherOutputStream.write(trailingBuffer, 0, bytesToWriteIntoOutput);
          mac.update(trailingBuffer, 0, bytesToWriteIntoOutput);
          System.arraycopy(trailingBuffer, bytesToWriteIntoOutput, trailingBuffer, 0,
                  trailingCount - bytesToWriteIntoOutput);
        }
        int trailingBufferOffset = trailingCount - bytesToWriteIntoOutput;
        System.arraycopy(buffer, 0, trailingBuffer, trailingBufferOffset,  readCount);
        trailingCount = trailingBufferOffset + readCount;
      }
    }

    cipherOutputStream.close();
    var calculatedMac = ByteUtil.trim(mac.doFinal(), 8);
    if (Arrays.compare(trailingBuffer, calculatedMac) != 0) {
      throw new InvalidMessageException("Bad Mac! Got " + Base64.getEncoder().encodeToString(trailingBuffer)
      + " calculated " + Base64.getEncoder().encodeToString(calculatedMac));
    }
  }
}