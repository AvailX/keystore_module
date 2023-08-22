package com.example.keystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.keystore.KeyStoreModule.KnownCiphers;
import com.example.keystore.cipherStorage.CipherStorage;
import com.example.keystore.cipherStorage.CipherStorage.EncryptionResult;

import java.util.HashSet;
import java.util.Set;

public class PrefsStorage {
  public static final String KEYCHAIN_DATA = "AV_KEYCHAIN";

  static public class ResultSet extends CipherStorage.CipherResult<byte[]> {
    @KnownCiphers
    public final String cipherStorageName;

    public ResultSet(@KnownCiphers final String cipherStorageName, final byte[] p_key, final byte[] v_key) {
      super(p_key, v_key);

      this.cipherStorageName = cipherStorageName;
    }
  }

  @NonNull
  private final SharedPreferences prefs;

  public PrefsStorage(@NonNull final Context AContext) {
    this.prefs = AContext.getSharedPreferences(KEYCHAIN_DATA, Context.MODE_PRIVATE);
  }

  @Nullable
  public ResultSet getEncryptedEntry(@NonNull final String service) {
    byte[] bytesForPKey = getBytesForPKey(service);
    byte[] bytesForVKey = getBytesForVKey(service);
    String cipherStorageName = getCipherStorageName(service);

    // in case of wrong password or username
    if (bytesForPKey == null || bytesForVKey == null) {
      return null;
    }

    if (cipherStorageName == null) {
      // If the CipherStorage name is not found, we assume it is because the entry was written by an older
      // version of this library. The older version used Facebook Conceal, so we default to that.
      cipherStorageName = KnownCiphers.FB;
    }

    return new ResultSet(cipherStorageName, bytesForPKey,  bytesForVKey);

  }

  public void removeEntry(@NonNull final String service) {
    final String keyForPKey = getKeyForPKey(service);
    final String keyForVKey = getKeyForVKey(service);
    final String keyForCipherStorage = getKeyForCipherStorage(service);

    prefs.edit()
      .remove(keyForPKey)
      .remove(keyForVKey)
      .remove(keyForCipherStorage)
      .apply();
  }

  public void storeEncryptedEntry(@NonNull final String service, @NonNull final EncryptionResult encryptionResult) {
    final String keyForUsername = getKeyForPKey(service);
    final String keyForPassword = getKeyForVKey(service);
    final String keyForCipherStorage = getKeyForCipherStorage(service);

    prefs.edit()
      .putString(keyForUsername, Base64.encodeToString(encryptionResult.p_key, Base64.DEFAULT))
      .putString(keyForPassword, Base64.encodeToString(encryptionResult.v_key, Base64.DEFAULT))
      .putString(keyForCipherStorage, encryptionResult.cipherName)
      .apply();
  }

  /**
   * List all types of cipher which are involved in en/decryption of the data stored herein.
   *
   * A cipher type is stored together with the datum upon encryption so the datum can later be decrypted using correct
   * cipher. This way, a {@link PrefsStorage} can involve different ciphers for different data. This method returns all
   * ciphers involved with this storage.
   *
   * @return set of cipher names
   */
  public Set<String> getUsedCipherNames() {
    Set<String> result = new HashSet<>();

    Set<String> keys = prefs.getAll().keySet();
    for (String key : keys) {
      if (isKeyForCipherStorage(key)) {
        String cipher = prefs.getString(key, null);
        result.add(cipher);
      }
    }

    return result;
  }

  @Nullable
  private byte[] getBytesForPKey(@NonNull final String service) {
    final String key = getKeyForPKey(service);

    return getBytes(key);
  }

  @Nullable
  private byte[] getBytesForVKey(@NonNull final String service) {
    String key = getKeyForVKey(service);
    return getBytes(key);
  }

  @Nullable
  private String getCipherStorageName(@NonNull final String service) {
    String key = getKeyForCipherStorage(service);

    return this.prefs.getString(key, null);
  }

  @NonNull
  public static String getKeyForPKey(@NonNull final String service) {
    return service + ":" + "p";
  }

  @NonNull
  public static String getKeyForVKey(@NonNull final String service) {
    return service + ":" + "v";
  }

  @NonNull
  public static String getKeyForCipherStorage(@NonNull final String service) {
    return service + ":" + "c";
  }

  public static boolean isKeyForCipherStorage(@NonNull final String key) {
    return key.endsWith(":c");
  }

  @Nullable
  private byte[] getBytes(@NonNull final String key) {
    String value = this.prefs.getString(key, null);

    if (value != null) {
      return Base64.decode(value, Base64.DEFAULT);
    }

    return null;
  }
}
