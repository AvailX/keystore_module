package com.example.keystore.cipherStorage;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.keystore.SecurityLevel;
import com.example.keystore.decryptionHandler.DecryptionResultHandler;
import com.example.keystore.exceptions.CryptoFailedException;
import com.example.keystore.exceptions.KeyStoreAccessException;

import java.security.Key;
import java.util.Set;

@SuppressWarnings({"unused", "WeakerAccess"})
public interface CipherStorage {
  //region Helper classes

  /** basis for storing keys in different data type formats. */
  abstract class CipherResult<T> {
    public final T p_key;
    public final T v_key;

    public CipherResult(final T p_key, final T v_key) {
      this.p_key = p_key;
      this.v_key = v_key;
    }
  }

  /** Credentials in bytes array, often a result of encryption. */
  class EncryptionResult extends CipherResult<byte[]> {
    /** Name of used for encryption cipher storage. */
    public final String cipherName;

    /** Main constructor. */
    public EncryptionResult(final byte[] p_key, final byte[] v_key, final String cipherName) {
      super(p_key, v_key);
      this.cipherName = cipherName;
    }

    /** Helper constructor. Simplifies cipher name extraction. */
    public EncryptionResult(final byte[] p_key, final byte[] v_key, @NonNull final CipherStorage cipherStorage) {
      this(p_key, v_key, cipherStorage.getCipherStorageName());
    }
  }

  /** Credentials in string's, often a result of decryption. */
  class DecryptionResult extends CipherResult<byte[]> {
    private final SecurityLevel securityLevel;

    public DecryptionResult(final byte[] p_key, final byte[] v_key) {
      this(p_key, v_key, SecurityLevel.ANY);
    }

    public DecryptionResult(final byte[] p_key, final byte[] v_key, final SecurityLevel level) {
      super(p_key, v_key);
      securityLevel = level;
    }

    public SecurityLevel getSecurityLevel() {
      return securityLevel;
    }
  }

  /** Ask access permission for decrypting credentials in provided context. */
  class DecryptionContext extends CipherResult<byte[]> {
    public final Key key;
    public final String keyAlias;

    public DecryptionContext(@NonNull final String keyAlias,
                             @NonNull final Key key,
                             @NonNull final byte[] v_key,
                             @NonNull final byte[] p_key) {
      super(p_key, v_key);
      this.keyAlias = keyAlias;
      this.key = key;
    }
  }

  //region API

  /** Encrypt credentials with provided key (by alias) and required security level. */
  @NonNull
  EncryptionResult encrypt(@NonNull final String alias,
                           @NonNull final byte[] p_key,
                           @NonNull final byte[] v_key,
                           @NonNull final SecurityLevel level)
    throws CryptoFailedException;

  /**
   * Decrypt credentials with provided key (by alias) and required security level.
   * In case of key stored in weaker security level than required will be raised exception.
   * That can happens during migration from one version of library to another.
   */
  @NonNull
  DecryptionResult decrypt(@NonNull final String alias,
                           @NonNull final byte[] p_key,
                           @NonNull final byte[] v_key,
                           @NonNull final SecurityLevel level)
    throws CryptoFailedException;

  /** Decrypt the credentials but redirect results of operation to handler. */
  void decrypt(@NonNull final DecryptionResultHandler handler,
               @NonNull final String alias,
               @NonNull final byte[] p_key,
               @NonNull final byte[] v_key,
               @NonNull final SecurityLevel level)
    throws CryptoFailedException;

  /** Remove key (by alias) from storage. */
  void removeKey(@NonNull final String alias) throws KeyStoreAccessException;

  /**
   * Return all keys present in this storage.
   * @return key aliases
   */
  Set<String> getAllKeys() throws KeyStoreAccessException;

  //endregion

  //region Configuration

  /** Storage name. */
  String getCipherStorageName();

  /** Minimal API level needed for using the storage. */
  int getMinSupportedApiLevel();

  /** Provided security level. */
  SecurityLevel securityLevel();

  /** True - based on secured hardware capabilities, otherwise False. */
  boolean supportsSecureHardware();

  /** True - based on biometric capabilities, otherwise false. */
  boolean isBiometrySupported();

  /**
   * The higher value means better capabilities.
   * Formula:
   * = 1000 * isBiometrySupported() +
   * 100 * isSecureHardware() +
   * minSupportedApiLevel()
   */
  int getCapabilityLevel();

  /** Get default name for alias/service. */
  String getDefaultAliasServiceName();
  //endregion
}
