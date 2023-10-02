package com.example.keystore.cipherStorage;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.keystore.SecurityLevel;
import com.example.keystore.exceptions.CryptoFailedException;
import com.example.keystore.exceptions.KeyStoreAccessException;
import com.example.keystore.decryptionHandler.DecryptionResultHandler;
import com.example.keystore.KeyStoreModule.KnownCiphers;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class CipherStorageKeystoreAesCbc extends CipherStorageBase{
  
  //region Constants
  /** AES */
  public static final String ALGORITHM_AES = KeyProperties.KEY_ALGORITHM_AES;
  /** CBC */
  public static final String BLOCK_MODE_CBC = KeyProperties.BLOCK_MODE_CBC;
  /** PKCS7 */
  public static final String PADDING_PKCS7 = KeyProperties.ENCRYPTION_PADDING_PKCS7;
  /** Transformation path. */
  public static final String ENCRYPTION_TRANSFORMATION =
    ALGORITHM_AES + "/" + BLOCK_MODE_CBC + "/" + PADDING_PKCS7;
  /** Key size. */
  public static final int ENCRYPTION_KEY_SIZE = 256;

  public static final String DEFAULT_SERVICE = "AV_KEYCHAIN_DEFAULT_ALIAS";
  
  /** For Salting Purposes. */
  private static final Random RANDOM = new SecureRandom();
  private static final int ITERATIONS = 10000;
  private static final int KEY_LENGTH = 256;

  //endregion

  //region Configuration
  @Override
  public String getCipherStorageName() {
    return KnownCiphers.AES;
  }

  /** API23 is a requirement. */
  @Override
  public int getMinSupportedApiLevel() {
    return Build.VERSION_CODES.M;
  }

  /** it can guarantee security levels up to SECURE_HARDWARE/SE/StrongBox */
  @Override
  public SecurityLevel securityLevel() {
    return SecurityLevel.SECURE_HARDWARE;
  }

  /** Biometry is Not Supported. */
  @Override
  public boolean isBiometrySupported() {
    return false;
  }

  /** AES. */
  @Override
  @NonNull
  protected String getEncryptionAlgorithm() {
    return ALGORITHM_AES;
  }

  /** AES/CBC/PKCS7Padding */
  @NonNull
  @Override
  protected String getEncryptionTransformation() {
    return ENCRYPTION_TRANSFORMATION;
  }

  /** {@inheritDoc}. Override for saving the compatibility with previous version of lib. */
  @Override
  public String getDefaultAliasServiceName() {
    return DEFAULT_SERVICE;
  }

  //endregion

  //region Overrides
  @Override
  @NonNull
  public EncryptionResult encrypt(@NonNull final String alias,
                                  @NonNull final byte[] p_key,
                                  @NonNull final byte[] v_key,
                                  @NonNull final SecurityLevel level)
    throws CryptoFailedException {

    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());
    final AtomicInteger retries = new AtomicInteger(1);

    try {
      final Key key = extractGeneratedKey(safeAlias, level, retries);
     
      //key changed to aesKey
      return new EncryptionResult(
        encryptBytes(key, p_key),
        encryptBytes(key, v_key),
        this);
    } catch (GeneralSecurityException e) {
      throw new CryptoFailedException("Could not encrypt data with alias: " + alias, e);
    } catch (Throwable fail) {
      throw new CryptoFailedException("Unknown error with alias: " + alias +
        ", error: " + fail.getMessage(), fail);
    }
  }

  @Override
  @NonNull
  public DecryptionResult decrypt(@NonNull final String alias,
                                  @NonNull final byte[] p_key,
                                  @NonNull final byte[] v_key,
                                  @NonNull final SecurityLevel level,
                                  @NonNull final boolean key_type)
    throws CryptoFailedException {

    throwIfInsufficientLevel(level);

    final String safeAlias = getDefaultAliasIfEmpty(alias, getDefaultAliasServiceName());
    final AtomicInteger retries = new AtomicInteger(1);

    try {
      final Key key = extractGeneratedKey(safeAlias, level, retries);

      return new DecryptionResult(
        decryptBytes(key, p_key),
        decryptBytes(key, v_key),
        getSecurityLevel(key));
    } catch (GeneralSecurityException e) {
      throw new CryptoFailedException("Could not decrypt data with alias: " + alias, e);
    } catch (Throwable fail) {
      throw new CryptoFailedException("Unknown error with alias: " + alias +
        ", error: " + fail.getMessage(), fail);
    }
  }

  /** Redirect call to {@link #decrypt(String, byte[], byte[], SecurityLevel, boolean)} method. */
  @Override
  public void decrypt(@NonNull final DecryptionResultHandler handler,
                      @NonNull final String service,
                      @NonNull final byte[] username,
                      @NonNull final byte[] password,
                      @NonNull final SecurityLevel level,
                      @NonNull final boolean key_type) {
    try {
      final DecryptionResult results = decrypt(service, username, password, level,key_type);

      handler.onDecrypt(results, null);
    } catch (Throwable fail) {
      handler.onDecrypt(null, fail);
    }
  }
  //endregion

  //region Implementation

  /** Get builder for encryption and decryption operations with required user Authentication. */
  @NonNull
  @Override
  protected KeyGenParameterSpec.Builder getKeyGenSpecBuilder(@NonNull final String alias) throws GeneralSecurityException {
    return getKeyGenSpecBuilder(alias, false);
  }

  /** Get encryption algorithm specification builder instance. */
  @NonNull
  @Override
  protected KeyGenParameterSpec.Builder getKeyGenSpecBuilder(@NonNull final String alias, @NonNull final boolean isForTesting)
    throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final int purposes = KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT;

     /* 
      KeyGenParameterSpec.Builder builder =  new KeyGenParameterSpec.Builder(alias, purposes)
      .setBlockModes(BLOCK_MODE_CBC)
      .setEncryptionPaddings(PADDING_PKCS7)
      .setRandomizedEncryptionRequired(true)
      .setUserAuthenticationRequired(true)
      .setKeySize(ENCRYPTION_KEY_SIZE);
    
      if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R){
        builder.setUserAuthenticationParameters(5, KeyProperties.AUTH_DEVICE_CREDENTIAL);
      }else{
        builder.setUserAuthenticationValidityDurationSeconds(5);
      } 
      
     return builder;
      */
    return new KeyGenParameterSpec.Builder(alias, purposes)
    .setBlockModes(BLOCK_MODE_CBC)
    .setEncryptionPaddings(PADDING_PKCS7)
    .setRandomizedEncryptionRequired(true)
    .setKeySize(ENCRYPTION_KEY_SIZE);


  }

  /** Get information about provided key. */
  @NonNull
  @Override
  protected KeyInfo getKeyInfo(@NonNull final Key key) throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE_TYPE);
    final KeySpec keySpec = factory.getKeySpec((SecretKey) key, KeyInfo.class);

    return (KeyInfo) keySpec;
  }

  /** Try to generate key from provided specification. */
  @NonNull
  @Override
  protected Key generateKey(@NonNull final KeyGenParameterSpec spec) throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      throw new KeyStoreAccessException("Unsupported API" + Build.VERSION.SDK_INT + " version detected.");
    }

    final KeyGenerator generator = KeyGenerator.getInstance(getEncryptionAlgorithm(), KEYSTORE_TYPE);

    // initialize key generator
    generator.init(spec);

    return generator.generateKey();
  }

  /** Decrypt provided bytes to a string. */
  @NonNull
  @Override
  protected byte[] decryptBytes(@NonNull final Key key, @NonNull final byte[] bytes,
                                @Nullable final DecryptBytesHandler handler)
    throws GeneralSecurityException, IOException {
    final Cipher cipher = getCachedInstance();

    try {
      // read the initialization vector from bytes array
      final IvParameterSpec iv = IV.readIv(bytes);
      cipher.init(Cipher.DECRYPT_MODE, key, iv);

      // decrypt the bytes using cipher.doFinal(). Using a CipherInputStream for decryption has historically led to issues
      // on the Pixel family of devices.
      // see https://github.com/oblador/react-native-keychain/issues/383
      byte[] decryptedBytes = cipher.doFinal(bytes, IV.IV_LENGTH, bytes.length - IV.IV_LENGTH);
      return decryptedBytes;
    } catch (Throwable fail) {
      Log.w(LOG_TAG, fail.getMessage(), fail);

      throw fail;
    }
  }
  //endregion

  //region Initialization Vector encrypt/decrypt support
  @NonNull
  @Override
  public byte[] encryptBytes(@NonNull final Key key, @NonNull final byte[] value)
    throws GeneralSecurityException, IOException {

    return encryptBytes(key, value, IV.encrypt);
  }

  @NonNull
  @Override
  public byte[] decryptBytes(@NonNull final Key key, @NonNull final byte[] bytes)
    throws GeneralSecurityException, IOException {
    return decryptBytes(key, bytes, IV.decrypt);
  }
  //endregion
  
}
